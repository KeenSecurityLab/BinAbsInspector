package com.bai.checkers;

import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.solver.CallGraph;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.StringUtils;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.util.List;
import java.util.Set;
import java.util.ArrayList;

/**
 * CWE-426: Untrusted Search Path
 */
public class CWE426 extends CheckerBase {

    private final Set<String> privilegeFunctions = Set.of(
            "setuid", "setreuid", "setresuid", "setresgid", "seteuid", "setegid"
    );
    private final Set<String> execFunctions = Set.of(
            "system", "popen"
    );

    public CWE426() {
        super("CWE426", "0.1");
        description = "Untrusted Search Path: The application searches for critical resources "
                + "using an externally-supplied search path that can point to resources that "
                + "are not under the application's direct control.";
    }

    private boolean checkFunctionParameters(AbsEnv absEnv, Function callee, Address address) {
        String name = callee.getName();
        // In case of both `system()` and `popen()` the path parameter is the first one
        if (callee.getParameterCount() < 1) {
            // Skip the call since Ghidra didn't detect suitable number of arguments
            Logging.debug("Not enough parameters for \"" + name + "()\" function");
            return false;
        }
        boolean result = false;
        KSet argKSet = getParamKSet(callee, 0, absEnv);
        if (!argKSet.isNormal()) {
            return false;
        }
        for (AbsVal ptrAbsVal : argKSet) {
            String str = StringUtils.getString(ptrAbsVal, absEnv);
            if (str == null) {
                continue;
            }
            // TODO: Improve distinction between absolute addresses and relative ones
            if (str.indexOf('/') != 0) {
                CWEReport report = getNewReport("Relative path \"" + str + "\" found for \""
                        + name + "()\" call").setAddress(address);
                Logging.report(report);
                result = true;
            }
        }
        return result;
    }

    private ArrayList<Address> hasPathToSymbols(CallGraph callGraph, Function function, ArrayList<Symbol> symbols) {
        ArrayList<Address> result = new ArrayList<>();
        for (Symbol symbol : symbols) {
            Function function2 = GlobalState.flatAPI.getFunctionAt(symbol.getAddress());
            if (function2 == null) {
                continue;
            }
            if (callGraph.hasPath(function, function2)) {
                // We get all references and check if function address matches with "To"
                for (Reference ref : symbol.getReferences()) {
                    // If a function symbol has a reference with type RefType.THUNK,
                    // then it is a thunk function.
                    if (ref.getReferenceType() == RefType.THUNK) {
                        break;
                    }
                    if (ref.getToAddress().equals(function2.getEntryPoint())) {
                        result.add(ref.getFromAddress());
                    }
                }
            }
        }
        return result;
    }

    private boolean isSymbolThunk(Symbol symbol) {
        // Find all callers of this symbol
        for (Reference ref : symbol.getReferences()) {
            // If a function symbol has a reference with type RefType.THUNK,
            // then it is a thunk function. We skip those.
            if (ref.getReferenceType() == RefType.THUNK) {
                return true;
            }
        }
        return false;
    }

    @Override
    public boolean check() {
        boolean hasWarning = false;
        try {
            SymbolTable symbolTable = GlobalState.currentProgram.getSymbolTable();
            if (symbolTable == null) {
                Logging.debug("Empty symbols table");
                return false;
            }
            Function entryFunction = null;
            if (GlobalState.config.getEntryAddress() != null) {
                entryFunction = GlobalState.flatAPI.getFunctionAt(
                        GlobalState.flatAPI.toAddr(GlobalState.config.getEntryAddress()));
            } else {
                List<Function> mainFunctions = GlobalState.flatAPI.getGlobalFunctions("main");
                if (mainFunctions.isEmpty()) {
                    return false;
                }
                entryFunction = mainFunctions.get(0);
            }
            CallGraph callGraph = CallGraph.getCallGraph(entryFunction);
            // 1st strategy:
            // When we find `system()` function, we check if
            // there is a path from the functions calling privilege-dropping
            // functions to these `system()` functions.
            ArrayList<Symbol> execSymbols = new ArrayList<>();
            for (Symbol symbol : symbolTable.getAllSymbols(true)) {
                if (execFunctions.contains(symbol.getName()) && symbol.hasReferences()
                        && !isSymbolThunk(symbol)) {
                    Logging.debug("Has exec \"" + symbol.getName() + "()\" symbol at " + symbol.getAddress());
                    execSymbols.add(symbol);
                }
            }
            for (Reference reference : Utils.getReferences(new ArrayList<>(privilegeFunctions))) {
                    Address fromAddress = reference.getFromAddress();
                    Logging.debug(fromAddress + "->" + reference.getToAddress());
                    Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
                    if (caller == null) {
                        continue;
                    }
                    Logging.debug("Checking path from \"" + caller.getName() + "\" privilege-dropping functions");
                    ArrayList<Address> callAddresses = hasPathToSymbols(callGraph, caller, execSymbols);
                    for (Address address : callAddresses) {
                        CWEReport report = getNewReport(
                                "Unsafe use of system()/popen()\"").setAddress(address);
                        Logging.report(report);
                        hasWarning = true;
                    }
            }
            Logging.debug("Checking the exec()-like function parameters...");
            // 2nd strategy:
            // Check if the paths supplied to system()-like functions are absolute
            // Since we don't have a string domains yet, we just check if the
            // first byte of the string is `/` (only for *NIX systems)
            for (Reference reference: Utils.getReferences(new ArrayList<>(execFunctions))) {
                Address toAddress = reference.getToAddress();
                Address fromAddress = reference.getFromAddress();
                Function callee = GlobalState.flatAPI.getFunctionAt(toAddress);
                Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
                if (callee == null || caller == null) {
                    Logging.debug("Skipping reference");
                    continue;
                }
                Logging.debug(fromAddress + " -> " + toAddress + " " + callee.getName());
                for (Context context : Context.getContext(caller)) {
                    AbsEnv absEnv = context.getAbsEnvIn().get(fromAddress);
                    if (absEnv == null) {
                        continue;
                    }
                    Logging.debug("Checking parameters for " + callee.getName() + " " + fromAddress);
                    hasWarning |= checkFunctionParameters(absEnv, callee, fromAddress);
                }
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return hasWarning;
    }
}

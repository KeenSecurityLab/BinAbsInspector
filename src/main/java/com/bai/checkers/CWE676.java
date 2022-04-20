package com.bai.checkers;

import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.solver.CallGraph;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * CWE-676: Use of Potentially Dangerous Function
 */
public class CWE676 extends CheckerBase {

    private static final Set<String> dangerousFunctions = Set.of(
            "gets",
            "strcpy",
            "operator>>" // only if the argument is "std::cin"
    );

    public CWE676() {
        super("CWE676", "0.1");
        description = "Use of Potentially Dangerous Function: The program invokes a potentially dangerous function "
                + "that could introduce a vulnerability if it is used incorrectly, "
                + "but the function can also be used safely.";
    }

    private boolean hasPathToSymbol(CallGraph callGraph, Function function, Symbol symbol) {
        Function function2 = GlobalState.flatAPI.getFunctionAt(symbol.getAddress());
        if (function2 == null) {
            return false;
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
                    return true;
                }
            }
        }
        return false;
    }

    private boolean handleStdCin(AbsEnv absEnv, CallGraph callGraph,
            Address fromAddress, Function callee, Function caller,
            SymbolIterator stdCins, SymbolIterator stdioWidths) {
        String name = callee.getName();
        if (!name.equals("operator>>")) {
            return false;
        }
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
        Logging.debug("Checking abstract values for " + argKSet.toString());
        for (AbsVal argAbsVal : argKSet) {
            // We skip non-global regions and big integer values
            if (argAbsVal.isBigVal() || !argAbsVal.getRegion().isGlobal()) {
                continue;
            }
            long address = argAbsVal.getValue();
            for (Symbol stdcin : stdCins) {
                if (stdcin.getAddress().getUnsignedOffset() == address) {
                    // We might have found a use of a pattern `std::cin >> buffer`
                    result = true;
                }
            }
        }
        // Check if we also have a call to `std::ios_base::width(cin->ios_base)`
        for (Symbol stdiowidth : stdioWidths) {
            if (stdiowidth.getParentNamespace().getName().equals("ios_base")) {
                Logging.debug("Has a reference to \"std::ios_base::width()\" at "
                        + stdiowidth.getAddress().toString());
                // Likely a valid constraint of the input buffer
                if (hasPathToSymbol(callGraph, caller, stdiowidth)) {
                    result = false;
                }
            }
        }
        if (result) {
            CWEReport report = getNewReport("\"std::cin >> buffer\" pattern found for \""
                    + name + "()\" call").setAddress(fromAddress);
            Logging.report(report);
        }
        return result;
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
            // Build a callgraph starting from the `main()` function.
            CallGraph callGraph = CallGraph.getCallGraph(entryFunction);
            SymbolIterator stdCins = symbolTable.getSymbols("cin");
            SymbolIterator stdioWidths = symbolTable.getSymbols("width");
            for (Reference reference: Utils.getReferences(new ArrayList<>(dangerousFunctions))) {
                Address toAddress = reference.getToAddress();
                Address fromAddress = reference.getFromAddress();
                Function callee = GlobalState.flatAPI.getFunctionAt(toAddress);
                Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
                if (callee == null || caller == null) {
                    continue;
                }
                Logging.debug(fromAddress + " -> " + toAddress + " " + callee.getName());
                // We have two cases - simple and complex (with std::cin)
                if (!callee.getName().equals("operator>>")) {
                    // Show report for the simple case
                    CWEReport report = getNewReport("Use of the dangerous function \""
                            + callee + "()\"").setAddress(fromAddress);
                    Logging.report(report);
                    hasWarning = true;
                    continue;
                }
                Logging.debug("std::operator>> case");
                if (stdCins == null) {
                    Logging.debug("std::cin not found");
                    continue;
                }
                // Now we process the more complex case of `std::cin >>`
                // Get the list of contexts for the current function
                for (Context context : Context.getContext(caller)) {
                    AbsEnv absEnv = context.getAbsEnvIn().get(fromAddress);
                    if (absEnv == null) {
                        continue;
                    }
                    hasWarning |= handleStdCin(absEnv, callGraph,
                            fromAddress, callee, caller, stdCins, stdioWidths);
                }
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return hasWarning;
    }
}

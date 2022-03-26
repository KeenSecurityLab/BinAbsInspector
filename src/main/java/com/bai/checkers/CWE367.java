package com.bai.checkers;

import com.bai.solver.CallGraph;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * CWE-367: Time-of-check Time-of-use (TOCTOU) Race Condition
 */
public class CWE367 extends CheckerBase {

    private final Set<String> accessName = Set.of("access", "stat");
    private final String openName = "open";

    public CWE367() {
        super("CWE367", "0.1");
        description = "Time-of-check Time-of-use (TOCTOU) Race Condition: The software checks the state of a resource "
                + "before using that resource, but the resource's state can change between the check and the use "
                + "in a way that invalidates the results of the check. "
                + "This can cause the software to perform invalid actions when the resource is in an unexpected state.";
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
            // When we find `access()`,`stat` and `open()` function, we check if
            // there is a path from the top function called `access()` or 'stat()' and then
            // the `open()` function and there are functions in between
            ArrayList<Symbol> accessSymbols = new ArrayList<>();
            ArrayList<Symbol> openSymbols = new ArrayList<>();

            for (Symbol symbol : symbolTable.getAllSymbols(true)) {

                if (accessName.contains(symbol.getName()) && symbol.hasReferences()
                        && !isSymbolThunk(symbol)) {
                    Logging.debug("Has \"" + symbol.getName() + "()\" symbol at " + symbol.getAddress());
                    accessSymbols.add(symbol);
                }
                if (openName.equals(symbol.getName()) && symbol.hasReferences()
                        && !isSymbolThunk(symbol)) {
                    Logging.debug("Has \"" + openName + "()\" symbol at " + symbol.getAddress());
                    openSymbols.add(symbol);
                }
            }
            for (Symbol symbol : accessSymbols) {
                // Find all callers of this symbol
                for (Reference ref : symbol.getReferences()) {
                    Address fromAddress = ref.getFromAddress();
                    Logging.debug(fromAddress + "->" + ref.getToAddress());
                    Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
                    if (caller == null) {
                        continue;
                    }
                    Logging.debug("\"" + symbol.getName() + "()\" called at " + fromAddress.toString()
                            + " from \"" + caller.getName() + "()\" function");
                    Logging.debug("Checking path from \"" + caller.getName() + "()\" to \""
                            + openName + "()\"");
                    ArrayList<Address> addresses = hasPathToSymbols(callGraph, caller, openSymbols);
                    for (Address address : addresses) {
                        CWEReport report = getNewReport(
                                "Possible TOCTOU combination \"" + symbol.getName() + "()\" and \""
                                        + openName + "()\"").setAddress(
                                address);
                        Logging.report(report);
                        hasWarning = true;
                    }
                }
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return hasWarning;
    }
}

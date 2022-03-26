package com.bai.checkers;

import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.Map;

/**
 * CWE-467: Use of sizeof() on a Pointer Type
 */
public class CWE467 extends CheckerBase {

    public CWE467() {
        super("CWE467", "0.1");
        description = "Use of sizeof() on a Pointer Type: The code calls sizeof() on a malloced pointer type, "
                + "which always returns the wordsize/8. This can produce an unexpected result "
                + "if the programmer intended to determine how much memory has been allocated.";
    }

    private static final Map<String, Integer> interestingSymbols = Map.of(
            "strncpy", 2,
            "strncmp", 2,
            "strncat", 2,
            "memcpy", 2,
            "malloc", 0,
            "alloca", 0,
            "_alloca", 0,
            "wcsncpy", 2,
            "memmove", 2,
            "wmemmove", 2
    );

    private boolean checkFunctionParameters(AbsEnv absEnv, Function callee, Address address) {
        String name = callee.getName();
        int paramIndex = interestingSymbols.get(name);
        if (paramIndex >= callee.getParameterCount()) {
            // Skip the call since Ghidra didn't detect suitable number of arguments
            Logging.debug("Not enough parameters for \"" + name + "()\" function");
            return false;
        }
        boolean result = false;
        KSet argKSet = getParamKSet(callee, paramIndex, absEnv);
        if (!argKSet.isNormal()) {
            return false;
        }
        for (AbsVal argAbsVal : argKSet) {
            // We skip non-global regions and big integer values
            if (argAbsVal.isBigVal() || !argAbsVal.getRegion().isGlobal()) {
                continue;
            }
            if (argAbsVal.getValue() == GlobalState.currentProgram.getDefaultPointerSize()) {
                // We might have found a use of a pattern `sizeof(ptr)`
                CWEReport report = getNewReport("Sizeof(ptr) pattern found for \""
                        + name + "()\" call").setAddress(address);
                Logging.report(report);
                result = true;
            }
        }
        return result;
    }

    @Override
    public boolean check() {
        boolean hasWarning = false;
        try {
            for (Reference reference : Utils.getReferences(new ArrayList<>(interestingSymbols.keySet()))) {
                Address toAddress = reference.getToAddress();
                Address fromAddress = reference.getFromAddress();
                Function callee = GlobalState.flatAPI.getFunctionAt(toAddress);
                Function caller = GlobalState.flatAPI.getFunctionContaining(fromAddress);
                if (callee == null || caller == null) {
                    continue;
                }
                Logging.debug(fromAddress + " -> " + toAddress + " " + callee.getName());
                // Get the list of contexts for the current function
                for (Context context : Context.getContext(caller)) {
                    AbsEnv absEnv = context.getAbsEnvIn().get(fromAddress);
                    if (absEnv == null) {
                        continue;
                    }
                    hasWarning |= checkFunctionParameters(absEnv, callee, fromAddress);
                }
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return hasWarning;
    }
}

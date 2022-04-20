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
import java.util.List;
import java.util.Set;

/**
 * CWE-732: Incorrect Permission Assignment for Critical Resource
 */
public class CWE732 extends CheckerBase {

    public CWE732() {
        super("CWE732", "0.1");
        description = "Incorrect Permission Assignment for Critical Resource: The product specifies permissions "
                + "for a security-critical resource in a way that allows that resource to be read or "
                + "modified by unintended actors.";
    }

    private static final String umaskName = "umask";
    // TODO: We also should check if there are arguments for writing/creation
    private static final Set<String> fileSymbols = Set.of("fopen", "open");

    // umask values could be set separately for group and all
    // We return warning in case of "all"
    // TODO: Add more strategies in the future
    private boolean isUnintendedPermission(long mode) {
        return mode == 0;
    }

    private boolean checkFunctionParameters(AbsEnv absEnv, Function callee, Address address) {
        String name = callee.getName();
        if (callee.getParameterCount() < 1) {
            // Skip the call since Ghidra didn't detect suitable number of arguments
            Logging.debug("Not enough parameters for \"" + name + "()\" function");
            return false;
        }
        KSet argKSet = getParamKSet(callee, 0, absEnv);
        if (!argKSet.isNormal()) {
            Logging.debug("Abnormal KSet");
            return false;
        }
        if (!argKSet.isSingleton()) {
            return false;
        }
        AbsVal argAbsVal = argKSet.iterator().next();
        // We skip non-global regions and big integer values
        if (argAbsVal.isBigVal() || !argAbsVal.getRegion().isGlobal()) {
            return false;
        }
        if (isUnintendedPermission(argAbsVal.getValue())) {
            // We might have found a use of a pattern `umask(chmod-style argument)`
            CWEReport report = getNewReport(
                    "Possibly incorrect permission assignment for critical resource pattern found for \""
                            + name + "()\" call").setAddress(address);
            Logging.report(report);
            return true;
        }
        return false;
    }

    @Override
    public boolean check() {
        boolean hasWarning = false;
        for (Reference reference : Utils.getReferences(List.of(umaskName))) {
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
        return hasWarning;
    }
}

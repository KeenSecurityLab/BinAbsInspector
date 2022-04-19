package com.bai.checkers;

import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.TaintMap;
import com.bai.env.TaintMap.Source;
import com.bai.env.region.RegionBase;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * CWE-134: Use of Externally-Controlled Format String
 */
public class CWE134 extends CheckerBase {

    public CWE134() {
        super("CWE134", "0.1");
        description = "Use of Externally-Controlled Format String: The software uses a function that "
                + "accepts a format string as an argument, but the format string originates from an external source.";
    }

    private static final Map<String, Integer> interestingSymbols = Map.of(
            "printf", 0,
            "sprintf", 1,
            "snprintf", 2,
            "fprintf", 1,
            "scanf", 0,
            "__iso99_scanf", 0,
            "sscanf", 1,
            "__iso99_sscanf", 1,
            "vprintf", 0,
            "vfprintf", 1
    );

    private static boolean isAbsValWriteable(AbsVal ptr) {
        RegionBase region = ptr.getRegion();
        if (region.isLocal() || region.isHeap()) {
            return true;
        }
        if (region.isGlobal() && !ptr.isBigVal()) {
            Address address = GlobalState.flatAPI.toAddr(ptr.getValue());
            MemoryBlock memoryBlock = GlobalState.flatAPI.getMemoryBlock(address);
            if (memoryBlock == null) {
                return false;
            }
            return memoryBlock.isWrite();
        }
        return false;
    }

    private boolean isTaintSourceFromEntry(Source source) {
        return source.getFunction().equals(GlobalState.eEntryFunction);
    }

    private boolean checkFunctionParameters(Context context, AbsEnv absEnv, Function callee, Address address) {
        String name = callee.getName();
        int paramIndex = interestingSymbols.get(name);
        Logging.debug("Processing argument " + paramIndex + " at " + name + "()");
        if (callee.getParameterCount() < paramIndex) {
            Logging.debug("Not enough parameters for \"" + name + "()\" function");
            return false;
        }
        boolean result = false;
        KSet argKSet = getParamKSet(callee, paramIndex, absEnv);
        if (argKSet.isTaint()) {
            long taints = argKSet.getTaints();
            List<Source> taintSourceList = TaintMap.getTaintSourceList(taints);
            for (TaintMap.Source taintSource : taintSourceList) {
                if (isTaintSourceFromEntry(taintSource)) {
                    Logging.debug("*argv appears in argument!");
                    CWEReport report = getNewReport(
                            "Potentially externally controlled format string from source of \"argv\" to \""
                                    + name + "()\"").setAddress(address);
                    Logging.report(report);
                    return true;
                }
            }
        }
        if (!argKSet.isNormal()) {
            return false;
        }
        Logging.debug("KSet for argument: " + argKSet);
        for (AbsVal argAbsVal : argKSet) {
            if (!isAbsValWriteable(argAbsVal)) {
                Logging.debug("Argument is not writeable: " + argAbsVal);
                continue;
            }
            Logging.debug("Argument is writeable: " + argAbsVal);
            CWEReport report = getNewReport("Potentially externally controlled format string \""
                    + name + "()\" call").setAddress(address);
            Logging.report(report);
            result = true;
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
                for (Context context : Context.getContext(caller)) {
                    AbsEnv absEnv = context.getAbsEnvIn().get(fromAddress);
                    if (absEnv == null) {
                        continue;
                    }
                    hasWarning |= checkFunctionParameters(context, absEnv, callee, fromAddress);
                }
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return hasWarning;
    }

}

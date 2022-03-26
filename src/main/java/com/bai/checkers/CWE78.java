package com.bai.checkers;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.TaintMap;
import com.bai.env.TaintMap.Source;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.StringUtils;
import com.bai.util.Utils;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.javimmutable.collections.JImmutableMap.Entry;

/**
 * CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
 */
public class CWE78 extends CheckerBase {

    public CWE78() {
        super("CWE78", "0.1");
        description = "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection'): "
                + "The software constructs all or part of an OS command using externally-influenced input from "
                + "an upstream component, but it does not neutralize or incorrectly neutralizes special elements that "
                + "could modify the intended OS command when it is sent to a downstream component.";
    }

    private static final Map<String, int[]> taintDstSymbols = Map.of(
            "system", new int[]{0},
            "popen", new int[]{0},
            "execl", new int[]{1, 2, 3, 4, 5},
            "execlp", new int[]{1, 2, 3, 4, 5}
    );

    private void defineExecSignature(Function function, String name, int argCount) {
        if (argCount == function.getParameters().length) {
            return;
        }
        try {
            final int tid = GlobalState.currentProgram.startTransaction("define signature");
            FunctionDefinitionDataType signature = new FunctionDefinitionDataType(name);
            ArrayList<ParameterDefinitionImpl> paramList = new ArrayList<>();
            for (int i = 0; i < argCount; i++) {
                paramList.add(new ParameterDefinitionImpl("arg" + i, PointerDataType.dataType, "arg" + i));
            }
            ParameterDefinitionImpl[] params = new ParameterDefinitionImpl[paramList.size()];
            signature.setArguments(paramList.toArray(params));
            signature.setReturnType(PointerDataType.dataType);
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                    function.getEntryPoint(),
                    signature,
                    SourceType.USER_DEFINED
            );
            cmd.applyTo(GlobalState.currentProgram, TaskMonitor.DUMMY);
            GlobalState.currentProgram.endTransaction(tid, true);
        } catch (Exception e) {
            Logging.warn("Fail to define signature for " + name);
        }
    }

    /**
     * Get first taint value from str, return null if the str is not tainted.
     *
     * @param ptr the pointer to str
     * @param absEnv
     * @return taint value, null if the str is not tainted
     */
    private Long getStrTaints(AbsVal ptr, AbsEnv absEnv) {
        int len = StringUtils.strlen(ptr, absEnv);
        int offset = 0;
        while (offset < len) {
            ALoc aLoc = ALoc.getALoc(ptr.getRegion(), ptr.getValue() + offset, 1);
            Entry<ALoc, KSet> entry = absEnv.getOverlapEntry(aLoc);
            if (entry == null) {
                return null;
            }
            if (entry.getValue().isTaint()) {
                return entry.getValue().getTaints();
            }
            offset += entry.getKey().getLen();
        }
        return null;
    }

    private boolean reportTaints(long taints, int idx, String funcName, Address address) {
        List<Source> taintSourceList = TaintMap.getTaintSourceList(taints);
        for (TaintMap.Source taintSource : taintSourceList) {
            CWEReport report = getNewReport("Potential OS Command Injection "
                    + "from source of "
                    + taintSource.getFunction().getName() + "(" + taintSource.getContext().toString()
                    + ") at " + Utils.getOrdinal(idx + 1) + " argument of \""
                    + funcName + "()\" call").setAddress(address);
            Logging.report(report);
            return true;
        }
        return false;
    }

    private boolean checkFunctionParameters(AbsEnv absEnv, Function callee, Address address) {
        String name = callee.getName();
        int[] paramIndexes = taintDstSymbols.get(name);
        int argCount = Arrays.stream(paramIndexes).max().getAsInt() + 1;
        if (callee.getParameters().length != argCount) {
            // define function signature for taintDstSymbols, which missing function model.
            defineExecSignature(callee, name, argCount);
        }
        boolean result = false;
        for (int idx : paramIndexes) {
            KSet ptrKSet = getParamKSet(callee, idx, absEnv);
            if (ptrKSet.isTop()) {
                if (ptrKSet.isTaint()) {
                    long taints = ptrKSet.getTaints();
                    result = reportTaints(taints, idx, name, address);
                    return result;
                }
                return false;
            }
            for (AbsVal ptr : ptrKSet) {
                Long taints = getStrTaints(ptr, absEnv);
                if (taints == null) {
                    continue;
                }
                result = reportTaints(taints, idx, name, address);
                if (result) {
                    return true;
                }
            }
        }
        return result;
    }

    @Override
    public boolean check() {
        boolean hasWarning = false;
        try {
            for (Reference reference : Utils.getReferences(new ArrayList<>(taintDstSymbols.keySet()))) {
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
                    hasWarning |= checkFunctionParameters(absEnv, callee, fromAddress);
                }
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return hasWarning;
    }
}

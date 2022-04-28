package com.bai.checkers;

import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.funcs.FunctionModelManager;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.funcs.externalfuncs.FreeFunction;
import com.bai.env.funcs.externalfuncs.VarArgsFunctionBase;
import com.bai.env.region.Heap;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer <br>
 * CWE-125: Out-of-bounds Read <br>
 * CWE-415: Double Free <br>
 * CWE-416: Use After Free <br>
 * CWE-476: NULL Pointer Dereference <br>
 * CWE-787: Out-of-bounds Write <br>
 */
public class MemoryCorruption {

    public static final int TYPE_READ = 0;
    public static final int TYPE_WRITE = 1;
    public static final int TYPE_ARGS = 2;

    public static final String CWE119 = "CWE119"; // Buffer Overflow (Generic case)
    public static final String CWE125 = "CWE125"; // Out-of-bounds Read
    public static final String CWE415 = "CWE415"; // Double Free
    public static final String CWE416 = "CWE416"; // Use After Free
    public static final String CWE476 = "CWE476"; // NULL Pointer Dereference
    public static final String CWE787 = "CWE787"; // Out-of-bounds Write
    public static final String VERSION = "0.1";

    // Safe unit to write beyond recorded stack size, because it's not always accurate to get real stack size from SP,
    // this could reduce false positive of CWE787.
    private static int getSafeUnitCnt() {
        return GlobalState.arch.isX86() ? 1 : 0;
    }

    private static final Map<String, List<Integer>> nullPointerDeferenceCallWhiteListMap = new HashMap<>();

    private static boolean shouldCheckNullPointerArg(String functionName, int idx) {
        List<Integer> indexes = new ArrayList<>();
        if (!nullPointerDeferenceCallWhiteListMap.containsKey(functionName)) {
            ExternalFunctionBase functionModel = FunctionModelManager.getExternalFunction(functionName);
            if (functionModel != null) {
                indexes = functionModel.getPointerParameterIndexes();
            }
            nullPointerDeferenceCallWhiteListMap.put(functionName, indexes);
        } else {
            indexes = nullPointerDeferenceCallWhiteListMap.get(functionName);
        }
        for (int i : indexes) {
            if (i == idx) {
                return true;
            }
        }
        return false;
    }

    /**
     * @hidden
     * @param kSet
     * @param address
     * @param context
     * @param callee
     * @param type
     * @param argIndex
     * @return
     */
    public static boolean checkNullPointerDereference(KSet kSet, Address address, Context context, Function callee,
            int type, int argIndex) {
        if (!kSet.isNormal() || !kSet.isSingleton()) {
            return true;
        }
        AbsVal ptr = kSet.iterator().next();
        String details = null;
        if (ptr.getRegion().isGlobal() && ptr.isZero()) {
            switch (type) {
                case TYPE_READ:
                    details = "Null pointer dereference Read";
                    break;
                case TYPE_WRITE:
                    details = "Null pointer dereference Write";
                    break;
                case TYPE_ARGS:
                    details =
                            "Null pointer dereference when Call to \"" + callee.getName(false) + "\" at "
                                    + Utils.getOrdinal(argIndex + 1) + " argument";
                    break;
                default: // nothing
            }
            CWEReport report = new CWEReport(CWE476, VERSION, details)
                    .setAddress(address)
                    .setContext(context);
            Logging.report(report);
            return false;
        }
        return true;
    }

    /**
     * @hidden
     * @param ptr
     * @param address
     * @param context
     * @param callee
     * @param type
     * @return
     */
    public static boolean checkUseAfterFree(AbsVal ptr, Address address, Context context, Function callee, int type) {
        assert ptr.getRegion().isHeap();
        Heap chunk = (Heap) ptr.getRegion();
        String details = null;
        if (!chunk.isValid()) {
            switch (type) {
                case TYPE_READ:
                    details = "Use After Free Read";
                    break;
                case TYPE_WRITE:
                    details = "Use After Free Write";
                    break;
                case TYPE_ARGS:
                    // skip double free cases.
                    if (FreeFunction.getStaticSymbols().contains(callee.getName(false))) {
                        return false;
                    }
                    details = "Use After Free when Call to " + callee.getName(false);
                    break;
                default: // nothing
            }
            details += " for chunk allocated at " + chunk.getAllocAddress() + ", when access";
            CWEReport report = new CWEReport(CWE416, VERSION, details)
                    .setAddress(address)
                    .setContext(context);
            Logging.report(report);
            return false;
        }
        return true;
    }

    /**
     * @hidden
     * @param ptr
     * @param address
     * @param context
     * @return
     */
    public static boolean checkDoubleFree(AbsVal ptr, Address address, Context context) {
        assert ptr.getRegion().isHeap();
        Heap chunk = (Heap) ptr.getRegion();
        if (!chunk.isValid()) {
            CWEReport report = new CWEReport(CWE415, VERSION, "Double Free")
                    .setAddress(address)
                    .setContext(context);
            Logging.report(report);
            return false;
        }
        return true;
    }

    private static boolean checkHeapOutOfBound(AbsVal ptr, Address address, Context context, Function callee,
            int type) {
        if (ptr.getOffset() < 0 || ptr.getOffset() >= ptr.getRegion().getSize()) {
            String details = null;
            String cwe = null;
            switch (type) {
                case TYPE_READ:
                    details = "Heap Out-of-Bound Read";
                    cwe = CWE125;
                    break;
                case TYPE_WRITE:
                    details = "Heap Out-of-Bound Write";
                    cwe = CWE787;
                    break;
                case TYPE_ARGS:
                    details = "Heap Out-of-Bound when Call to " + callee.getName(false);
                    cwe = CWE119;
                    break;
                default: // nothing
            }
            Logging.debug("Check OOB for: " + ptr + " at " + address.toString() + "," + context.toString());
            details += " for chunk allocated at " + ((Heap) ptr.getRegion()).getAllocAddress() + ", when access";
            CWEReport report = new CWEReport(cwe, VERSION, details)
                    .setAddress(address)
                    .setContext(context);
            Logging.report(report);
            return false;
        }
        return true;
    }

    private static boolean checkStackOutOfBound(AbsVal ptr, Address address, Context context, Function callee,
            int type) {

        long offset = ptr.getOffset();
        if (Utils.isLeafFunction(context.getFunction()) && offset < 0) {
            // suppress false positive on leaf function
            return true;
        }
        if (offset >= 0 && type != TYPE_WRITE) {
            // Access to a parameter or the return address of the function
            return true;
        }
        offset = Math.abs(offset);
        if (offset > ptr.getRegion().getSize() + ((long) getSafeUnitCnt() * GlobalState.arch.getDefaultPointerSize())) {
            String details = "Stack Out-of-Bound Write";
            String cwe = CWE787;
            Logging.debug("Check OOB for: " + ptr + " at " + address.toString() + "," + context);
            CWEReport report = new CWEReport(cwe, VERSION, details)
                    .setAddress(address)
                    .setContext(context);
            Logging.report(report);
            return false;
        }
        return true;
    }

    /**
     * @hidden
     * @param ptr
     * @param address
     * @param context
     * @param callee
     * @param type
     * @return
     */
    public static boolean checkOutOfBound(AbsVal ptr, Address address, Context context, Function callee, int type) {
        assert ptr.getRegion().isHeap() || ptr.getRegion().isLocal();
        if (ptr.getRegion().isHeap()) {
            Heap chunk = (Heap) ptr.getRegion();
            if (chunk.isValid()) {
                return checkHeapOutOfBound(ptr, address, context, callee, type);
            }
        } else if (ptr.getRegion().isLocal()) {
            return checkStackOutOfBound(ptr, address, context, callee, type);
        }
        return false;
    }

    /**
     * @hidden
     * @param pcode
     * @param inOutEnv
     * @param tmpEnv
     * @param context
     * @param calleeFunc
     * @return
     */
    public static boolean checkExternalCallParameters(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv,
            Context context, Function calleeFunc) {
        boolean isCheckPasss = true;
        Address address = Utils.getAddress(pcode);
        String functionName = calleeFunc.getName(false);
        if (FreeFunction.getStaticSymbols().contains(functionName)) {
            KSet pKSet = ExternalFunctionBase.getParamKSet(calleeFunc, 0, inOutEnv);
            if (!pKSet.isNormal()) {
                return false;
            }
            for (AbsVal argAbsVal : pKSet) {
                if (!argAbsVal.getRegion().isHeap()) {
                    continue;
                }
                isCheckPasss |= checkDoubleFree(argAbsVal, address, context);
                if (!isCheckPasss) { // stop checking once detected.
                    return isCheckPasss;
                }
            }
        }

        int paramCount;
        Address callSite = Utils.getAddress(pcode);
        FunctionDefinition signature = VarArgsFunctionBase.getVarArgsSignature(callSite);
        if (signature == null) {
            signature = (FunctionDefinition) calleeFunc.getSignature();
            paramCount = calleeFunc.getParameterCount();
        } else {
            paramCount = signature.getArguments().length;
        }

        for (int i = 0; i < paramCount; i++) {
            KSet pKset = ExternalFunctionBase.getVarArgsParamKSet(calleeFunc, signature, i, inOutEnv);
            if (!pKset.isNormal()) {
                continue;
            }
            if (shouldCheckNullPointerArg(functionName, i)) {
                isCheckPasss |= MemoryCorruption.checkNullPointerDereference(pKset, address, context, calleeFunc,
                        TYPE_ARGS, i);
            }
            for (AbsVal argAbsVal : pKset) {
                boolean hasUAF = false;
                if (argAbsVal.getRegion().isHeap()) {
                    hasUAF = !checkUseAfterFree(argAbsVal, address, context, calleeFunc, TYPE_ARGS);
                    isCheckPasss |= !hasUAF;
                }
                if (!hasUAF && !argAbsVal.getRegion().isGlobal()) {
                    isCheckPasss |= checkOutOfBound(argAbsVal, address, context, calleeFunc, TYPE_ARGS);
                    if (!isCheckPasss) { // stop checking once detected;
                        return isCheckPasss;
                    }
                }
            }
        }
        return isCheckPasss;
    }
}

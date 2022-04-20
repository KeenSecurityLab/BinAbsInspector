package com.bai.env.funcs.externalfuncs;


import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.Logging;
import com.bai.util.StringUtils;
import java.util.Set;


/**
 * char *strncpy(char *dest, const char *src, size_t n)
 */
public class StrncpyFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("strncpy");

    public StrncpyFunction() {
        super(staticSymbols);
        addDefaultParam("dst", PointerDataType.dataType);
        addDefaultParam("src", PointerDataType.dataType);
        addDefaultParam("n", IntegerDataType.dataType);
        setReturnType(PointerDataType.dataType);
    }

    private void copyString(AbsEnv inOutEnv, KSet dstPtrKSet, KSet srcPtrKSet, int size) {
        for (AbsVal srcPtr : srcPtrKSet) {
            if (srcPtr.isBigVal()) {
                continue;
            }
            for (AbsVal dstPtr : dstPtrKSet) {
                if (dstPtr.isBigVal()) {
                    continue;
                }
                StringUtils.copyString(dstPtr, srcPtr, inOutEnv, size);
            }
        }
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        if (retALoc == null) {
            return;
        }
        KSet dstPtrKSet = getParamKSet(calleeFunc, 0, inOutEnv);
        KSet srcPtrKSet = getParamKSet(calleeFunc, 1, inOutEnv);
        if (!dstPtrKSet.isNormal() || !srcPtrKSet.isNormal()) {
            return;
        }
        long size = 0;
        KSet sizeKSet = getParamKSet(calleeFunc, 2, inOutEnv);
        if (sizeKSet.isTop()) {
            copyString(inOutEnv, dstPtrKSet, srcPtrKSet, StringUtils.MAX_LEN);
            return;
        }
        for (AbsVal absVal : sizeKSet) {
            if (absVal.getRegion().isGlobal()) {
                if (absVal.isBigVal()) {
                    continue;
                }
                size = Math.max(size, Math.min(absVal.getValue(), StringUtils.MAX_LEN));
            }
        }
        if (size == 0) {
            size = StringUtils.MAX_LEN;
        }
        if (!srcPtrKSet.isSingleton() || !dstPtrKSet.isSingleton()) {
            Logging.warn("Handling non-singleton in " + calleeFunc.getName() + ", may lead to imprecise result.");
        }
        copyString(inOutEnv, dstPtrKSet, srcPtrKSet, (int) size);
        KSet newRet = new KSet(dstPtrKSet);
        inOutEnv.set(retALoc, newRet, true);
    }

}

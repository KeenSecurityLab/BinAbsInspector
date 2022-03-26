package com.bai.env.funcs.externalfuncs;


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
 * void *memcpy(void *str1, const void *str2, size_t n)
 */
public class MemcpyFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("memcpy");

    public MemcpyFunction() {
        super(staticSymbols);
        addDefaultParam("dest", PointerDataType.dataType);
        addDefaultParam("src", PointerDataType.dataType);
        addDefaultParam("n", IntegerDataType.dataType);
        setReturnType(PointerDataType.dataType);
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        KSet dstPtrKSet = getParamKSet(calleeFunc, 0, inOutEnv);
        KSet srcPtrKSet = getParamKSet(calleeFunc, 1, inOutEnv);
        KSet sizeKSet = getParamKSet(calleeFunc, 2, inOutEnv);
        if (!dstPtrKSet.isNormal() || !srcPtrKSet.isNormal() || !sizeKSet.isNormal()) {
            return;
        }
        long size = 0;
        for (AbsVal absVal : sizeKSet) {
            if (absVal.getRegion().isGlobal()) {
                //filter the bigval
                if (absVal.isBigVal()) {
                    continue;
                }
                size = Math.max(size, Math.min(StringUtils.MAX_LEN, absVal.getValue()));
            }
        }
        if (!srcPtrKSet.isSingleton() || !dstPtrKSet.isSingleton()) {
            Logging.warn("Handling non-singleton in memcpy, may lead to imprecise result.");
        }
        for (AbsVal srcPtr : srcPtrKSet) {
            if (srcPtr.isBigVal()) {
                continue;
            }
            for (AbsVal dstPtr : dstPtrKSet) {
                if (dstPtr.isBigVal()) {
                    continue;
                }
                StringUtils.copyString(dstPtr, srcPtr, inOutEnv, (int) size);
            }
        }
    }

}

package com.bai.env.funcs.externalfuncs;


import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.Logging;
import com.bai.util.StringUtils;

import java.util.Set;


/**
 * char *strcpy(char *dest, const char *src)
 */
public class StrcpyFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("strcpy");

    public StrcpyFunction() {
        super(staticSymbols);
        addDefaultParam("dst", PointerDataType.dataType);
        addDefaultParam("src", PointerDataType.dataType);
        setReturnType(PointerDataType.dataType);
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc) {
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        if (retALoc == null) {
            return;
        }
        KSet dstPtrKSet = getParamKSet(calleeFunc, 0, inOutEnv);
        KSet srcPtrKSet = getParamKSet(calleeFunc, 1, inOutEnv);
        if (dstPtrKSet.isTop() || srcPtrKSet.isTop()) {
            return;
        }
        if (!srcPtrKSet.isSingleton() || !dstPtrKSet.isSingleton()) {
            Logging.warn("Handling non-singleton in " + calleeFunc.getName() + ", may lead to imprecise result.");
        }
        for (AbsVal srcPtr : srcPtrKSet) {
            if (srcPtr.isBigVal()) {
                continue;
            }
            for (AbsVal dstPtr : dstPtrKSet) {
                if (dstPtr.isBigVal()) {
                    continue;
                }
                StringUtils.copyString(dstPtr, srcPtr, inOutEnv, StringUtils.MAX_LEN);
            }
        }
        KSet newRet = new KSet(dstPtrKSet);
        inOutEnv.set(retALoc, newRet, true);
    }

}

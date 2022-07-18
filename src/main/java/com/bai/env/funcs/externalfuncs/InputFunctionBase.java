package com.bai.env.funcs.externalfuncs;

import static com.bai.util.Utils.getAddress;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.TaintMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.Logging;
import com.bai.util.Utils;
import java.util.Set;

/**
 * The base class of input function models.
 */
public abstract class InputFunctionBase extends ExternalFunctionBase {

    protected int taintedBufParamIndex = -1;

    protected boolean isReturnNewTaint = false;

    /**
     * Setup which parameter is buffer and need to taint.
     * @param idx the parameter index.
     */
    protected void setTaintedBufParamIndex(int idx) {
        taintedBufParamIndex = idx;
    }

    /**
     * Setup whether taint the return value or not.
     * @param isReturnNewTaint true to taint, false otherwise.
     */
    protected void setReturnNewTaint(boolean isReturnNewTaint) {
        this.isReturnNewTaint = isReturnNewTaint;
    }

    protected InputFunctionBase(Set<String> symbols) {
        super(symbols);
    }

    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        if (retALoc == null) {
            return;
        }
        Address callAddress = getAddress(pcode);
        if (taintedBufParamIndex == -1) {
            if (isReturnNewTaint) {
                long newTaints = TaintMap.getTaints(callAddress, context, callFunc);
                inOutEnv.set(retALoc, KSet.getTop(newTaints), true);
            }
            return;
        }
        KSet res = new KSet(retALoc.getLen() * 8);
        for (ALoc bufALoc : getParamALocs(callFunc, taintedBufParamIndex, inOutEnv)) {
            KSet bufPtrKSet = inOutEnv.get(bufALoc);
            long newTaints = TaintMap.getTaints(callAddress, context, callFunc);

            if (!bufPtrKSet.isNormal()) {
                bufPtrKSet = KSet.getTop(newTaints);
                inOutEnv.set(bufALoc, bufPtrKSet, true);
            } else {
                for (AbsVal bufPtr : bufPtrKSet) {
                    Utils.taintBufWithTop(inOutEnv, bufPtr, newTaints);
                }
            }
            KSet union = res.join(bufPtrKSet);
            res = (union == null) ? res : union;
        }

        if (returnType == PointerDataType.dataType) {
            inOutEnv.set(retALoc, res, true);
        } else if (returnType == IntegerDataType.dataType) {
            inOutEnv.set(retALoc, KSet.getTop(), true);
        } else {
            Logging.warn("Undefined return data type for " + callFunc);
        }

    }

}

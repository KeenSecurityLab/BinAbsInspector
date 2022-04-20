package com.bai.env.funcs.externalfuncs;


import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.Utils;
import java.util.Set;


/**
 * char *strncat(char *dest, const char *src, size_t n)
 */
public class StrcatFunction extends ExternalFunctionBase {

    // TODO: maybe separate "strncat" to another model for better precision.
    private static final Set<String> staticSymbols = Set.of("strcat", "strncat");

    public StrcatFunction() {
        super(staticSymbols);
        addDefaultParam("dest", PointerDataType.dataType);
        addDefaultParam("src", PointerDataType.dataType);
        setReturnType(PointerDataType.dataType);
    }

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        KSet dstPtrKSet = getParamKSet(callFunc, 0, inOutEnv);
        KSet srcPtrKSet = getParamKSet(callFunc, 1, inOutEnv);

        long srcTaints = Utils.computePtrTaints(srcPtrKSet, inOutEnv);

        if (!dstPtrKSet.isNormal()) {
            long newTaints = dstPtrKSet.getTaints() | srcTaints;
            dstPtrKSet = dstPtrKSet.setTaints(newTaints);
            for (ALoc dstALoc : getParamALocs(callFunc, 0, inOutEnv)) {
                inOutEnv.set(dstALoc, dstPtrKSet, true);
            }
        } else {
            for (AbsVal ptr : dstPtrKSet) {
                Utils.taintBuf(inOutEnv, ptr, srcTaints, true);
            }
        }
        KSet resKSet = new KSet(dstPtrKSet);
        inOutEnv.set(retALoc, resKSet, true);
    }
}

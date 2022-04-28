package com.bai.env.funcs.externalfuncs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Set;

/**
 * size_t malloc_usable_size(void *ptr);
 */
public class MallocUsableSizeFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("malloc_usable_size");

    public MallocUsableSizeFunction() {
        super(staticSymbols);
        addDefaultParam("ptr", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
    }

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        if (retALoc == null) {
            return;
        }
        KSet argKSet = getParamKSet(callFunc, 0, inOutEnv);
        if (!argKSet.isNormal()) {
            return;
        }
        KSet resKSet = new KSet(retALoc.getLen() * 8);
        for (AbsVal ptr : argKSet) {
            if (!ptr.getRegion().isHeap()) {
                continue;
            }
            Heap chunk = (Heap) ptr.getRegion();
            if (chunk.getSize() != Heap.DEFAULT_SIZE) {
                resKSet = resKSet.insert(new AbsVal(chunk.getSize()));
            } else {
                // return TOP for undetermined allocate size
                resKSet = KSet.getTop();
                break;
            }
        }
        inOutEnv.set(retALoc, resKSet, true);
    }
}

package com.bai.env.funcs.externalfuncs;

import static com.bai.util.Utils.getAddress;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Set;
import org.javimmutable.collections.JImmutableMap.Entry;
import org.javimmutable.collections.JImmutableSet;

/**
 * void *realloc(void *ptr, size_t size)
 */
public class ReallocFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("realloc");

    public ReallocFunction() {
        super(staticSymbols);
        addDefaultParam("ptr", PointerDataType.dataType);
        addDefaultParam("size", IntegerDataType.dataType);
        setReturnType(PointerDataType.dataType);
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        if (retALoc == null) {
            return;
        }
        KSet ptrKSet = getParamKSet(callFunc, 0, inOutEnv);
        if (!ptrKSet.isNormal()) {
            return;
        }
        Address freeSiteAddress = getAddress(pcode);
        for (Entry<ALoc, KSet> entry : inOutEnv.getEnvMap()) {
            KSet oldKSet = entry.getValue();
            if (!oldKSet.isNormal()) {
                continue;
            }
            JImmutableSet<AbsVal> intersection = oldKSet.getInnerSet().intersection(ptrKSet.getInnerSet());
            KSet newKSet = new KSet(oldKSet);
            if (intersection.isEmpty()) {
                continue;
            }
            for (AbsVal oldAbsVal : intersection) {
                if (!oldAbsVal.getRegion().isHeap()) {
                    continue;
                }
                Heap invalidHeap = ((Heap) oldAbsVal.getRegion()).toInvalid(freeSiteAddress);
                newKSet = newKSet.remove(oldAbsVal).insert(AbsVal.getPtr(invalidHeap));
            }
            inOutEnv.set(entry.getKey(), newKSet, true);
        }
        long size = Heap.DEFAULT_SIZE;
        KSet sizeKSet = getParamKSet(callFunc, 1, inOutEnv);
        if (sizeKSet.isNormal()) {
            ArrayList<Long> sizeList = new ArrayList<>();
            for (AbsVal absVal : sizeKSet) {
                if (absVal.getRegion().isGlobal()) {
                    sizeList.add(absVal.getValue());
                }
            }
            size = sizeList.isEmpty() ? size : Collections.max(sizeList);
        }
        // If requested size is zero we skip the allocation part
        if (size == 0) {
            return;
        }
        Address allocAddress = getAddress(pcode);
        KSet resKSet = new KSet(retALoc.getLen() * 8);
        Heap allocChunk = Heap.getHeap(allocAddress, context, size, true);
        resKSet = resKSet.insert(AbsVal.getPtr(allocChunk));
        inOutEnv.set(retALoc, resKSet, true);
    }
}

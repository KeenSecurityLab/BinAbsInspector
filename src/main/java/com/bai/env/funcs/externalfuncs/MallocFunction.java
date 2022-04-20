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

/**
 * void *malloc(size_t size) <br>
 * void *xmalloc(size_t size) <br>
 * new <br>
 * new[]
 */
public class MallocFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("malloc", "operator.new", "operator.new[]", "xmalloc");

    public MallocFunction() {
        super(staticSymbols);
        addDefaultParam("size", IntegerDataType.dataType);
        setReturnType(PointerDataType.dataType);
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        if (retALoc == null) {
            return;
        }
        KSet allocSizeKSet = getParamKSet(callFunc, 0, inOutEnv);
        long size = Heap.DEFAULT_SIZE;
        if (allocSizeKSet.isNormal()) {
            ArrayList<Long> sizeList = new ArrayList<>();
            for (AbsVal absVal : allocSizeKSet) {
                if (absVal.getRegion().isGlobal()) {
                    sizeList.add(absVal.getValue());
                }
            }
            if (sizeList.size() != 0) {
                size = Collections.max(sizeList);
            }
        }
        Address allocAddress = getAddress(pcode);
        KSet resKSet = new KSet(retALoc.getLen() * 8);
        Heap allocChunk = Heap.getHeap(allocAddress, context, size, true);
        resKSet = resKSet.insert(AbsVal.getPtr(allocChunk));
        inOutEnv.set(retALoc, resKSet, true);
    }

}

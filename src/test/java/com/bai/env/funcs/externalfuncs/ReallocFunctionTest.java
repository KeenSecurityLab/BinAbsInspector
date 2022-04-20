package com.bai.env.funcs.externalfuncs;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.ARMProgramTestBase;
import org.junit.Test;
import org.mockito.Mockito;

public class ReallocFunctionTest extends ARMProgramTestBase {

    @Test
    public void testInvoke() {
        PcodeOp pcode = Utils.getMockCallPcodeOp();
        Context mockContext = Mockito.mock(Context.class);
        Function mockRealloc = Utils.getMockFunction("realloc",
                new DataType[]{PointerDataType.dataType, IntegerDataType.dataType}, PointerDataType.dataType);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        Heap heap1 = Heap.getHeap(Utils.getDefaultAddress(0x1010), mockContext, true);
        Heap heap2 = Heap.getHeap(Utils.getDefaultAddress(0x1020), mockContext, true);

        ALoc arg0ALoc = ALoc.getALoc(mockRealloc.getParameter(0).getFirstStorageVarnode());
        KSet argKSet = new KSet(32)
                .insert(AbsVal.getPtr(heap1))
                .insert(AbsVal.getPtr(heap2));
        inOutEnv.set(arg0ALoc, argKSet, true);

        ALoc r1ALoc = ALoc.getALoc(mockRealloc.getParameter(1).getFirstStorageVarnode());
        KSet sizeKSet = new KSet(32).insert(new AbsVal(0x400));
        inOutEnv.set(r1ALoc, sizeKSet, true);

        ExternalFunctionBase reallocFunc = new ReallocFunction();
        reallocFunc.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockRealloc);

        assert inOutEnv.get(arg0ALoc).isSingleton();
        KSet ptrKSet = inOutEnv.get(arg0ALoc);
        for (AbsVal ptr : ptrKSet) {
            Heap heap = (Heap) ptr.getRegion();
            assert heap.getSize() == 0x400;
        }

    }
}
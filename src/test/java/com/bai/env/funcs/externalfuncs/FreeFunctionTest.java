package com.bai.env.funcs.externalfuncs;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.ARMProgramTestBase;
import org.junit.Test;
import org.mockito.Mockito;

public class FreeFunctionTest extends ARMProgramTestBase {

    @Test
    public void testInvoke() {
        PcodeOp pcode = Utils.getMockCallPcodeOp();
        Context mockContext = Mockito.mock(Context.class);
        Function mockFree = Utils.getMockFunction("free", new DataType[]{PointerDataType.dataType},
                PointerDataType.dataType);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        ALoc arg0ALoc = ALoc.getALoc(mockFree.getParameter(0).getFirstStorageVarnode());
        KSet argKSet = new KSet(32)
                .insert(AbsVal.getPtr(Heap.getHeap(Utils.getDefaultAddress(0x1010), mockContext, true)))
                .insert(AbsVal.getPtr(Heap.getHeap(Utils.getDefaultAddress(0x1020), mockContext, 0, false)));

        inOutEnv.set(arg0ALoc, argKSet, true);
        ExternalFunctionBase freeFunc = new FreeFunction();
        freeFunc.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockFree);
        KSet ptrKSet = inOutEnv.get(arg0ALoc);
        for (AbsVal ptr : ptrKSet) {
            Heap heap = (Heap) ptr.getRegion();
            assert !heap.isValid();
        }
    }
}
package com.bai.env.funcs.externalfuncs;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import com.bai.util.ARMProgramTestBase;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Iterator;
import org.junit.Test;
import org.mockito.Mockito;

public class AllocFunctionTest extends ARMProgramTestBase {

    @Test
    public void testInvokeMalloc() {
        PcodeOp pcode = Utils.getMockCallPcodeOp();
        Context mockContext = Mockito.mock(Context.class);
        Function mockMalloc = Utils.getMockFunction("malloc", new DataType[]{IntegerDataType.dataType},
                PointerDataType.dataType);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        ALoc r0ALoc = ALoc.getALoc(mockMalloc.getParameter(0).getFirstStorageVarnode());
        KSet argKSet = new KSet(32)
                .insert(new AbsVal(0x10))
                .insert(new AbsVal(0x20))
                .insert(new AbsVal(0x1000));

        inOutEnv.set(r0ALoc, argKSet, true);
        ExternalFunctionBase allocFunc = new MallocFunction();
        allocFunc.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockMalloc);

        assert inOutEnv.get(r0ALoc).isSingleton();
        Iterator<AbsVal> iterator = inOutEnv.get(r0ALoc).getInnerSet().iterator();
        AbsVal absVal = iterator.next();
        assert absVal.getRegion().isHeap();
        Heap heap = (Heap) absVal.getRegion();
        assert heap.getSize() == 0x1000;
    }

    @Test
    public void testInvokeCalloc() {
        PcodeOp pcode = Utils.getMockCallPcodeOp();

        Context mockContext = Mockito.mock(Context.class);
        Function mockCalloc = Utils.getMockFunction("calloc",
                new DataType[]{IntegerDataType.dataType, IntegerDataType.dataType}, PointerDataType.dataType);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        ALoc arg0ALoc = ALoc.getALoc(mockCalloc.getParameter(0).getFirstStorageVarnode());
        ALoc arg1ALoc = ALoc.getALoc(mockCalloc.getParameter(1).getFirstStorageVarnode());
        KSet nKset = new KSet(32).insert(new AbsVal(4));
        KSet sizeKSet = new KSet(32)
                .insert(new AbsVal(0x10))
                .insert(new AbsVal(0x20))
                .insert(new AbsVal(0x1000));

        inOutEnv.set(arg0ALoc, nKset, true);
        inOutEnv.set(arg1ALoc, sizeKSet, true);
        ExternalFunctionBase allocFunc = new CallocFunction();
        allocFunc.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockCalloc);

        assert inOutEnv.get(arg0ALoc).isSingleton();
        Iterator<AbsVal> iterator = inOutEnv.get(arg0ALoc).getInnerSet().iterator();
        AbsVal absVal = iterator.next();
        assert absVal.getRegion().isHeap();
        Heap heap = (Heap) absVal.getRegion();
        assert heap.getSize() == 0x4000;
    }
}
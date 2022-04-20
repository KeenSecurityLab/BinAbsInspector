package com.bai.env.funcs.externalfuncs;


import static org.mockito.Mockito.when;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.StringUtils;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.ARMProgramTestBase;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class StrcpyFunctionTest extends ARMProgramTestBase {

    @Test
    public void testInvokeStrcpy() {

        final PcodeOp pcode = Utils.getMockCallPcodeOp();
        Context mockContext = Mockito.mock(Context.class);
        Function mockStrcpy = Utils.getMockFunction("strcpy",
                new DataType[]{PointerDataType.dataType, PointerDataType.dataType}, PointerDataType.dataType);
        when(mockStrcpy.getName()).thenReturn("strcpy");
        final ALoc dstALoc = ALoc.getALoc(mockStrcpy.getParameter(0).getLastStorageVarnode());
        final ALoc srcALoc = ALoc.getALoc(mockStrcpy.getParameter(1).getLastStorageVarnode());
        final ALoc retALoc = ALoc.getALoc(mockStrcpy.getReturn().getLastStorageVarnode());
        Heap heap = Heap.getHeap(GlobalState.flatAPI.toAddr(0x1122), mockContext, true);

        final AbsEnv tmpEnv = new AbsEnv();
        AbsEnv inOutEnv = new AbsEnv();
        ALoc aloc1 = ALoc.getALoc(heap, 0x3000, 4);
        inOutEnv.set(aloc1, new KSet(32), true);
        ALoc aloc2 = ALoc.getALoc(heap, 0x4000, 4);
        inOutEnv.set(aloc2, new KSet(32).insert(new AbsVal(0x61620064)), true);
        //set dstAloc
        inOutEnv.set(dstALoc, new KSet(32).insert(new AbsVal(heap, 0x3000)), true);
        //set srcAloc
        inOutEnv.set(srcALoc, new KSet(32).insert(new AbsVal(heap, 0x4000)), true);
        StrcpyFunction strcpyFunction = new StrcpyFunction();
        strcpyFunction.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockStrcpy);
        assert inOutEnv.get(retALoc).equals(new KSet(32).insert(new AbsVal(heap, 0x3000)));
        assert inOutEnv.get(aloc1).isBot();

        inOutEnv = new AbsEnv();
        aloc1 = ALoc.getALoc(heap, 0x2000, 4);
        inOutEnv.set(aloc1, new KSet(32).insert(new AbsVal(0x30303030)), true);
        aloc2 = ALoc.getALoc(heap, 0x2500, 4);
        inOutEnv.set(aloc2, new KSet(32).insert(new AbsVal(0x1010)), true);
        //set dstAloc
        inOutEnv.set(dstALoc, new KSet(32).insert(new AbsVal(heap, 0x2000)), true);
        //set srcAloc
        inOutEnv.set(srcALoc, new KSet(32).insert(new AbsVal(heap, 0x2500)), true);
        strcpyFunction.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockStrcpy);
        assert inOutEnv.get(retALoc).equals(new KSet(32).insert(new AbsVal(heap, 0x2000)));
        System.out.println(inOutEnv.get(aloc1).iterator().next());
        assert inOutEnv.get(aloc1).iterator().next().equals(new AbsVal(0x30001010));

        inOutEnv = new AbsEnv();
        aloc1 = ALoc.getALoc(heap, 0x2700, 4);
        inOutEnv.set(aloc1, new KSet(32).insert(new AbsVal(0x12345678)), true);
        aloc2 = ALoc.getALoc(heap, 0x2800, 4);
        inOutEnv.set(aloc2, new KSet(32).insert(new AbsVal(0x22330044)), true);
        //set dstAloc
        inOutEnv.set(dstALoc, new KSet(32).insert(new AbsVal(heap, 0x2700)), true);
        //set srcAloc
        inOutEnv.set(srcALoc, new KSet(32).insert(new AbsVal(heap, 0x2800)), true);
        strcpyFunction.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockStrcpy);
        assert inOutEnv.get(aloc1).iterator().next().equals(new AbsVal(0x12340044));

        int txId = program.startTransaction("set str");
        MemoryBlock mem = programBuilder.createMemory(".data", "0x6000", 0x1000);
        mem.setRead(true);
        try {
            mem.putBytes(Utils.getDefaultAddress(0x6000), Utils.fromHexString("414243444546474849002234"));
        } catch (MemoryAccessException e) {
            Logging.error(e.toString());
        }
        program.endTransaction(txId, true);
        aloc1 = ALoc.getALoc(heap, 0x2900, 4);
        inOutEnv.set(dstALoc, new KSet(32).insert(new AbsVal(0x2900)), true);
        inOutEnv.set(srcALoc, new KSet(32).insert(new AbsVal(0x6000)), true);
        strcpyFunction.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockStrcpy);
        Assert.assertEquals(StringUtils.getString(inOutEnv.get(dstALoc).iterator().next(), inOutEnv), "ABCDEFGHI");

    }

}

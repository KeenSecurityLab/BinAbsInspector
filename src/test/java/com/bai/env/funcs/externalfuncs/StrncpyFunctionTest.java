package com.bai.env.funcs.externalfuncs;

import static org.mockito.Mockito.when;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import com.bai.util.ARMProgramTestBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.StringUtils;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;


import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class StrncpyFunctionTest extends ARMProgramTestBase {

    @Test
    public void testInvokeStrncpy() {
        final PcodeOp pcode = Utils.getMockCallPcodeOp();
        final Context mockContext = Mockito.mock(Context.class);
        final Function mockStrncpy = Utils.getMockFunction("strncpy",
                new DataType[]{PointerDataType.dataType, PointerDataType.dataType, IntegerDataType.dataType},
                PointerDataType.dataType);
        when(mockStrncpy.getName()).thenReturn("strncpy");
        final ALoc dstALoc = ALoc.getALoc(mockStrncpy.getParameter(0).getLastStorageVarnode());
        final ALoc srcALoc = ALoc.getALoc(mockStrncpy.getParameter(1).getLastStorageVarnode());
        final ALoc n = ALoc.getALoc(mockStrncpy.getParameter(2).getLastStorageVarnode());
        Heap heap = Heap.getHeap(GlobalState.flatAPI.toAddr(0x1122), mockContext, true);
        AbsEnv inOutEnv;
        final AbsEnv tmpEnv = new AbsEnv();
        inOutEnv = new AbsEnv();

        ALoc aloc1 = ALoc.getALoc(heap, 0x2000, 4);
        inOutEnv.set(aloc1, new KSet(32).insert(new AbsVal(0x30313233)), true);
        ALoc aloc2 = ALoc.getALoc(heap, 0x2500, 4);
        inOutEnv.set(aloc2, new KSet(32).insert(new AbsVal(0x66676869)), true);
        ALoc aloc3 = ALoc.getALoc(heap, 0x2504, 4);
        inOutEnv.set(aloc3, new KSet(32).insert(new AbsVal(0x00626364)), true);
        inOutEnv.set(dstALoc, new KSet(32).insert(new AbsVal(heap, 0x2000)), true);
        inOutEnv.set(srcALoc, new KSet(32).insert(new AbsVal(heap, 0x2500)), true);
        inOutEnv.set(n, new KSet(32).insert(new AbsVal(6)), true);
        StrncpyFunction strncpyFunction = new StrncpyFunction();
        strncpyFunction.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockStrncpy);
        assert StringUtils.getString(inOutEnv.get(dstALoc).iterator().next(), inOutEnv).equals("ihgfdc");
        aloc1 = ALoc.getALoc(heap, 0x2000, 4);
        inOutEnv.set(aloc1, new KSet(32).insert(new AbsVal(0x70)), true);
        aloc2 = ALoc.getALoc(heap, 0x2500, 4);
        inOutEnv.set(aloc2, new KSet(32).insert(new AbsVal(0x75767778)), true);
        aloc3 = ALoc.getALoc(heap, 0x2504, 4);
        inOutEnv.set(aloc3, new KSet(32).insert(new AbsVal(0x80818283)), true);
        inOutEnv.set(dstALoc, new KSet(32).insert(new AbsVal(heap, 0x2000)), true);
        inOutEnv.set(srcALoc, new KSet(32).insert(new AbsVal(heap, 0x2500)), true);
        inOutEnv.set(n, new KSet(32).insert(new AbsVal(4)), true);
        strncpyFunction.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockStrncpy);
        assert StringUtils.getString(inOutEnv.get(dstALoc).iterator().next(), inOutEnv).equals("xwvu");

        int txId = program.startTransaction("set str");
        MemoryBlock mem = programBuilder.createMemory(".data", "0x6000", 0x1000);
        mem.setRead(true);
        try {
            mem.putBytes(Utils.getDefaultAddress(0x6000), Utils.fromHexString("414243444546474849002234"));
        } catch (MemoryAccessException e) {
            Logging.error(e.toString());
        }
        program.endTransaction(txId, true);
        inOutEnv.set(dstALoc, new KSet(32).insert(new AbsVal(0x2900)), true);
        inOutEnv.set(srcALoc, new KSet(32).insert(new AbsVal(0x6000)), true);
        inOutEnv.set(n, new KSet(32).insert(new AbsVal(5)), true);
        strncpyFunction.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockStrncpy);
        Assert.assertEquals(StringUtils.getString(inOutEnv.get(dstALoc).iterator().next(), inOutEnv), "ABCDE");
    }

}

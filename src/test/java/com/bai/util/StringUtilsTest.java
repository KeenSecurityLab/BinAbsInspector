package com.bai.util;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Global;
import com.bai.env.region.Heap;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import java.math.BigInteger;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class StringUtilsTest extends ARMProgramTestBase {

    @Test
    public void testStrlen() {
        int txId = program.startTransaction("set str");
        MemoryBlock mem = programBuilder.createMemory(".data", "0x2000", 0x1000);
        mem.setRead(true);
        try {
            mem.putBytes(com.bai.Utils.getDefaultAddress(0x2000), com.bai.Utils.fromHexString("4142434445"));
        } catch (MemoryAccessException e) {
            Logging.error(e.toString());
        }
        program.endTransaction(txId, true);

        AbsVal ptrAbsVal = new AbsVal(Global.getInstance(), 0x2000);
        AbsEnv inOutEnv = new AbsEnv();

        int res = StringUtils.strlen(ptrAbsVal, inOutEnv);
        assert res == 5;

        inOutEnv = new AbsEnv();
        Context mockContext = Mockito.mock(Context.class);
        Heap heap = Heap.getHeap(GlobalState.flatAPI.toAddr(0x1122), mockContext, true);
        ALoc ptrALoc = ALoc.getALoc(heap, 0x3000, 4);
        inOutEnv.set(ptrALoc, new KSet(32).insert(new AbsVal(0x44434241)), true);
        ptrALoc = ALoc.getALoc(heap, 0x3004, 4);
        inOutEnv.set(ptrALoc, new KSet(32).insert(new AbsVal(0x4645)), true);
        ptrAbsVal = new AbsVal(heap, 0x3000);
        res = StringUtils.strlen(ptrAbsVal, inOutEnv);
        assert res == 6;

        ptrALoc = ALoc.getALoc(heap, 0x3008, 8);
        inOutEnv.set(ptrALoc, new KSet(64).insert(new AbsVal(BigInteger.valueOf(0xCCBBAAL))), true);
        ptrAbsVal = new AbsVal(heap, 0x3008);
        res = StringUtils.strlen(ptrAbsVal, inOutEnv);
        assert res == 3;
    }

    @Test
    public void testStrchr() {
        int txId = program.startTransaction("set str");
        MemoryBlock mem = programBuilder.createMemory(".data", "0x2000", 0x1000);
        mem.setRead(true);
        try {
            mem.putBytes(com.bai.Utils.getDefaultAddress(0x2000), com.bai.Utils.fromHexString("4142434445"));
        } catch (MemoryAccessException e) {
            Logging.error(e.toString());
        }
        program.endTransaction(txId, true);

        AbsVal ptrAbsVal = new AbsVal(Global.getInstance(), 0x2000);
        AbsEnv inOutEnv = new AbsEnv();

        int res = StringUtils.indexOf(ptrAbsVal, 'C', inOutEnv);
        assert res == 2;

        inOutEnv = new AbsEnv();
        Context mockContext = Mockito.mock(Context.class);
        Heap heap = Heap.getHeap(GlobalState.flatAPI.toAddr(0x1122), mockContext, true);
        ALoc ptrALoc = ALoc.getALoc(heap, 0x3000, 4);
        inOutEnv.set(ptrALoc, new KSet(32).insert(new AbsVal(0x44434241)), true);
        ptrALoc = ALoc.getALoc(heap, 0x3004, 4);
        inOutEnv.set(ptrALoc, new KSet(32).insert(new AbsVal(0x4645)), true);
        ptrAbsVal = new AbsVal(heap, 0x3000);
        res = StringUtils.indexOf(ptrAbsVal, 'F', inOutEnv);
        assert res == 5;

        ptrALoc = ALoc.getALoc(heap, 0x3008, 8);
        inOutEnv.set(ptrALoc, new KSet(64).insert(new AbsVal(BigInteger.valueOf(0xCCBBAAL))), true);
        ptrAbsVal = new AbsVal(heap, 0x3008);
        res = StringUtils.indexOf(ptrAbsVal, 'A', inOutEnv);
        assert res == -1;
    }

    @Test
    public void testGetString() {
        int txId = program.startTransaction("set str");
        MemoryBlock mem = programBuilder.createMemory(".data", "0x2000", 0x1000);
        mem.setRead(true);
        try {
            mem.putBytes(com.bai.Utils.getDefaultAddress(0x2000), Utils.fromHexString("4142434445"));
        } catch (MemoryAccessException e) {
            Logging.error(e.toString());
        }
        program.endTransaction(txId, true);

        AbsVal ptrAbsVal = new AbsVal(Global.getInstance(), 0x2000);
        AbsEnv inOutEnv = new AbsEnv();

        String res = StringUtils.getString(ptrAbsVal, inOutEnv);
        Assert.assertEquals(res, "ABCDE");

        inOutEnv = new AbsEnv();
        Context mockContext = Mockito.mock(Context.class);
        Heap heap = Heap.getHeap(GlobalState.flatAPI.toAddr(0x1122), mockContext, true);
        ALoc ptrALoc = ALoc.getALoc(heap, 0x3000, 4);
        inOutEnv.set(ptrALoc, new KSet(32).insert(new AbsVal(0x44434241)), true);
        ptrALoc = ALoc.getALoc(heap, 0x3004, 4);
        inOutEnv.set(ptrALoc, new KSet(32).insert(new AbsVal(0x4645)), true);
        ptrAbsVal = new AbsVal(heap, 0x3000);
        res = StringUtils.getString(ptrAbsVal, inOutEnv);
        Assert.assertEquals(res, "ABCDEF");

        ptrALoc = ALoc.getALoc(heap, 0x3008, 8);
        inOutEnv.set(ptrALoc, new KSet(64).insert(new AbsVal(BigInteger.valueOf(0x636261L))), true);
        ptrAbsVal = new AbsVal(heap, 0x3008);
        res = StringUtils.getString(ptrAbsVal, inOutEnv);
        Assert.assertEquals(res, "abc");
    }
}
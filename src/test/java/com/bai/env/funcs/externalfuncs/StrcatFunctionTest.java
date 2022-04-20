package com.bai.env.funcs.externalfuncs;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.TaintMap;
import com.bai.env.region.Global;
import com.bai.env.region.Heap;
import com.bai.util.ARMProgramTestBase;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import org.junit.Test;
import org.mockito.Mockito;

public class StrcatFunctionTest extends ARMProgramTestBase {

    @Test
    public void testInvokeStrcat() {
        PcodeOp pcode = Utils.getMockCallPcodeOp();
        Context mockContext = Mockito.mock(Context.class);
        Function mockStrcat = Utils.getMockFunction("strcat",
                new DataType[]{PointerDataType.dataType, PointerDataType.dataType}, PointerDataType.dataType);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        final ALoc dstALoc = ALoc.getALoc(mockStrcat.getParameter(0).getFirstStorageVarnode());
        final ALoc srcALoc = ALoc.getALoc(mockStrcat.getParameter(1).getFirstStorageVarnode());
        final ALoc retALoc = ALoc.getALoc(mockStrcat.getReturn().getFirstStorageVarnode());

        // dst = top, src = top
        inOutEnv.set(dstALoc, KSet.getTop(TaintMap.getTaints(0x10)), true);
        inOutEnv.set(srcALoc, KSet.getTop(TaintMap.getTaints(0x20)), true);
        ExternalFunctionBase strcatFunc = new StrcatFunction();
        strcatFunc.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockStrcat);

        assert inOutEnv.get(dstALoc).checkTaints(0x10);
        assert inOutEnv.get(dstALoc).checkTaints(0x20);
        assert inOutEnv.get(retALoc).checkTaints(0x10);
        assert inOutEnv.get(retALoc).checkTaints(0x20);

        // dst = normal, src = normal, taint from dst and src
        inOutEnv = new AbsEnv();
        Heap heap1 = Heap.getHeap(Utils.getDefaultAddress(0x1010), mockContext, true);
        KSet srcString = new KSet(32).insert(new AbsVal(0x41424344)).setTaints(TaintMap.getTaints(0x10));
        AbsVal srcPtr = new AbsVal(heap1, 0);
        KSet srcPtrKSet = new KSet(32).insert(srcPtr);
        ALoc srcPtrALoc = ALoc.getALoc(srcPtr.getRegion(), 0, 4);

        inOutEnv.set(srcPtrALoc, srcString, true);
        inOutEnv.set(srcALoc, srcPtrKSet, true);

        KSet dstString = new KSet(64).insert(new AbsVal(0x61616161)).setTaints(TaintMap.getTaints(0x20));
        AbsVal dstPtr = new AbsVal(Global.getInstance(), 0x3000);
        KSet dstPtrKSet = new KSet(32).insert(dstPtr);
        ALoc dstPtrALoc = ALoc.getALoc(dstPtr.getRegion(), 0x3000, 8);

        inOutEnv.set(dstPtrALoc, dstString, true);
        inOutEnv.set(dstALoc, dstPtrKSet, true);
        strcatFunc.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockStrcat);

        assert inOutEnv.get(dstPtrALoc).checkTaints(0x10);
        assert inOutEnv.get(dstPtrALoc).checkTaints(0x20);
        assert inOutEnv.get(retALoc).equals(inOutEnv.get(dstALoc));

    }

}
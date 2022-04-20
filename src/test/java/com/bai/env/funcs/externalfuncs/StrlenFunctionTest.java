package com.bai.env.funcs.externalfuncs;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import com.bai.env.region.Reg;
import com.bai.util.ARMProgramTestBase;
import com.bai.util.GlobalState;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import org.junit.Test;
import org.mockito.Mockito;

public class StrlenFunctionTest extends ARMProgramTestBase {

    @Test
    public void testInvokeStrlen() {
        final PcodeOp pcode = Utils.getMockCallPcodeOp();
        final Context mockContext = Mockito.mock(Context.class);
        final Function mockStrlen = Utils.getMockFunction("strlen", new DataType[]{IntegerDataType.dataType},
                IntegerDataType.dataType);


        final AbsEnv inOutEnv = new AbsEnv();
        final AbsEnv tmpEnv = new AbsEnv();
        Heap heap = Heap.getHeap(GlobalState.flatAPI.toAddr(0x1122), mockContext, true);
        ALoc ptrALoc = ALoc.getALoc(heap, 0x3000, 4);
        inOutEnv.set(ptrALoc, new KSet(32).insert(new AbsVal(0x44434241)), true);
        ptrALoc = ALoc.getALoc(heap, 0x3004, 4);
        inOutEnv.set(ptrALoc, new KSet(32).insert(new AbsVal(0x4645)), true);
        AbsVal ptrAbsVal = new AbsVal(heap, 0x3000);
        inOutEnv.set(Reg.getALoc("r0"), new KSet(32).insert(ptrAbsVal), true);

        ExternalFunctionBase strlenFunc = new StrlenFunction();
        strlenFunc.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockStrlen);

        KSet expect = new KSet(32).insert(new AbsVal(6));
        assert inOutEnv.get(Reg.getALoc("r0")).equals(expect);
    }

}
package com.bai.env.funcs.externalfuncs;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.util.Logging;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.ARMProgramTestBase;
import org.junit.Test;
import org.mockito.Mockito;

public class PrintfFunctionTest extends ARMProgramTestBase {

    @Test
    public void testInvokePrintf() {
        final Context mockContext = Mockito.mock(Context.class);
        Function mockPrintf = Utils.getMockFunction("printf",
                new DataType[]{PointerDataType.dataType}, IntegerDataType.dataType);
        final ALoc formatALoc = ALoc.getALoc(mockPrintf.getParameter(0).getLastStorageVarnode());
        int txId = program.startTransaction("set str");
        MemoryBlock mem = programBuilder.createMemory(".data", "0x6000", 0x1000);
        mem.setRead(true);
        try {
            mem.putBytes(Utils.getDefaultAddress(0x6000), Utils.fromHexString("25642025645c6e"));//"%d %d\n"
        } catch (MemoryAccessException e) {
            Logging.error(e.toString());
        }
        program.endTransaction(txId, true);

        AbsEnv inOutEnv = new AbsEnv();
        PcodeOp pcode = Utils.getMockCallPcodeOp();
        AbsEnv tmpEnv = new AbsEnv();
        inOutEnv.set(formatALoc, new KSet(32).insert(new AbsVal(0x6000)), true);
        PrintfFunction printfFunction = new PrintfFunction();
        printfFunction.invoke(pcode, inOutEnv, tmpEnv, mockContext, mockPrintf);
    }
}

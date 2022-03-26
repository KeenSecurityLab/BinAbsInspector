package com.bai.env.funcs.externalfuncs;

import com.bai.Utils;
import com.bai.util.StringUtils;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongDoubleDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.listing.Function;
import com.bai.util.ARMProgramTestBase;
import org.junit.Assert;
import org.junit.Test;

public class InputFunctionVarArgsBaseTest extends ARMProgramTestBase {

    @Test
    public void testFormatStringTypeField() {
        Function mockFunction = Utils.getMockFunction("mock", new DataType[]{PointerDataType.dataType},
                IntegerDataType.dataType);
        FunctionDefinition def = StringUtils.getFunctionSignature("%d", mockFunction);
        Assert.assertEquals(def.getArguments()[1].getDataType(), IntegerDataType.dataType);

        // integer
        def = StringUtils.getFunctionSignature("%hhd %hd %d %ld %lld", mockFunction);
        Assert.assertEquals(def.getArguments()[1].getDataType(), CharDataType.dataType);
        Assert.assertEquals(def.getArguments()[2].getDataType(), ShortDataType.dataType);
        Assert.assertEquals(def.getArguments()[3].getDataType(), IntegerDataType.dataType);
        Assert.assertEquals(def.getArguments()[4].getDataType(), LongDataType.dataType);
        Assert.assertEquals(def.getArguments()[5].getDataType(), LongLongDataType.dataType);

        // unsigned integer
        def = StringUtils.getFunctionSignature("%hhu %hu %u %lu %llu", mockFunction);
        Assert.assertEquals(def.getArguments()[1].getDataType(), UnsignedCharDataType.dataType);
        Assert.assertEquals(def.getArguments()[2].getDataType(), UnsignedShortDataType.dataType);
        Assert.assertEquals(def.getArguments()[3].getDataType(), UnsignedIntegerDataType.dataType);
        Assert.assertEquals(def.getArguments()[4].getDataType(), UnsignedLongDataType.dataType);
        Assert.assertEquals(def.getArguments()[5].getDataType(), UnsignedLongLongDataType.dataType);

        // float
        def = StringUtils.getFunctionSignature("%f %e %g %lf %Lf", mockFunction);
        Assert.assertEquals(def.getArguments()[1].getDataType(), FloatDataType.dataType);
        Assert.assertEquals(def.getArguments()[2].getDataType(), FloatDataType.dataType);
        Assert.assertEquals(def.getArguments()[3].getDataType(), FloatDataType.dataType);
        Assert.assertEquals(def.getArguments()[4].getDataType(), DoubleDataType.dataType);
        Assert.assertEquals(def.getArguments()[5].getDataType(), LongDoubleDataType.dataType);

        // pointer
        def = StringUtils.getFunctionSignature("%c %s %p", mockFunction);
        Assert.assertEquals(def.getArguments()[1].getDataType(), CharDataType.dataType);
        Assert.assertEquals(def.getArguments()[2].getDataType(), PointerDataType.getPointer(CharDataType.dataType, -1));
        Assert.assertEquals(def.getArguments()[3].getDataType(), PointerDataType.dataType);
    }

}
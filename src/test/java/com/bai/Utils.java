package com.bai;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.bai.solver.CFG;
import com.bai.util.Architecture;
import com.bai.util.GlobalState;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import java.math.BigInteger;
import java.util.Arrays;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

public class Utils {

    public static byte[] fromHexString(String src) {
        byte[] biBytes = new BigInteger("10" + src.replaceAll("\\s", ""), 16).toByteArray();
        return Arrays.copyOfRange(biBytes, 1, biBytes.length);
    }

    public static Address getConstantAddress(long offset) {
        return GlobalState.currentProgram.getAddressFactory().getConstantAddress(offset);
    }

    public static Address getDefaultAddress(long offset) {
        return GlobalState.currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
    }

    public static Address getRegisterAddress(long offset) {
        return GlobalState.currentProgram.getAddressFactory().getRegisterSpace().getAddress(offset);
    }

    public static Address getUniqueAddress(long offset) {
        return GlobalState.currentProgram.getAddressFactory().getUniqueSpace().getAddress(offset);
    }

    public static Varnode getRegVarnode(String name) {
        Register reg = GlobalState.currentProgram.getRegister(name);
        if (reg == null) {
            return null;
        }
        return new Varnode(reg.getAddress(), reg.getBitLength() / 8);
    }

    public static Function getMockFunction(String name, DataType[] argDataTypes, DataType returnDataType) {
        int argNum = argDataTypes.length;
        Function mockFunction = Mockito.mock(Function.class);
        when(mockFunction.getName()).thenReturn(name);
        Parameter[] parameters = new Parameter[argNum];
        PrototypeModel prototypeModel = GlobalState.currentProgram.getCompilerSpec().getDefaultCallingConvention();
        ParameterDefinitionImpl[] parameterDefinitions = new ParameterDefinitionImpl[argNum];
        for (int i = 0; i < argNum; i++) {
            VariableStorage variableStorage = prototypeModel.getArgLocation(i, null, argDataTypes[i],
                    GlobalState.currentProgram);
            Varnode paramVarnode = variableStorage.getFirstVarnode();
            Parameter argParameter = Mockito.mock(Parameter.class);
            parameters[i] = argParameter;
            parameterDefinitions[i] = new ParameterDefinitionImpl(null, argDataTypes[i], null);
            when(argParameter.getFirstStorageVarnode()).thenReturn(paramVarnode);
            when(argParameter.getLastStorageVarnode()).thenReturn(paramVarnode);
            when(mockFunction.getParameter(i)).thenReturn(argParameter);
        }
        when(mockFunction.getParameters()).thenReturn(parameters);

        VariableStorage retVariableStorage = prototypeModel.getStorageLocations(GlobalState.currentProgram,
                new DataType[]{returnDataType}, false)[0];
        Varnode retVarnode = retVariableStorage.getFirstVarnode();
        Parameter retParameter = Mockito.mock(Parameter.class);
        when(retParameter.getFirstStorageVarnode()).thenReturn(retVarnode);
        when(retParameter.getLastStorageVarnode()).thenReturn(retVarnode);
        when(mockFunction.getReturn()).thenReturn(retParameter);

        FunctionDefinitionDataType funcSignature = new FunctionDefinitionDataType(name);
        funcSignature.setArguments(parameterDefinitions);
        funcSignature.setReturnType(returnDataType);
        when(mockFunction.getSignature()).thenReturn(funcSignature);
        return mockFunction;
    }

    public static PcodeOp getMockCallPcodeOp() {
        Address instructionAddress = getDefaultAddress(0x1000);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);
        Varnode[] in = {new Varnode(getDefaultAddress(0x2000), GlobalState.arch.getDefaultPointerSize())};
        return new PcodeOp(seq, PcodeOp.CALL, in, null);
    }

    /**
     * mock cfg for worklist init in Context constructor.
     */
    public static void mockCfgForContext() {
        CFG mockCFG = Mockito.mock(CFG.class);
        when(mockCFG.getSum()).thenReturn(10);
        MockedStatic<CFG> mocked = Mockito.mockStatic(CFG.class);
        mocked.when(() -> CFG.getCFG(any())).thenReturn(mockCFG);
    }

    private static MockedStatic<Architecture> architectureMockedStatic = null;

    public static void mockArchitecture(boolean isLittleEndian) {
        Architecture mockArch = Mockito.mock(Architecture.class);
        when(mockArch.isLittleEndian()).thenReturn(isLittleEndian);
        when(mockArch.getDefaultPointerSize()).thenReturn(4);
        // fix test in PcodeVisitorTest.testVisitSUBPIECE
        when(mockArch.getPcIndex()).thenReturn(0x100);
        GlobalState.arch = mockArch;
    }
}

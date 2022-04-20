package com.bai.env.funcs.externalfuncs;


import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * int printf(const char *format, ...)
 */
public class PrintfFunction extends VarArgsFunctionBase {

    private static final Set<String> staticSymbols = Set.of("printf");

    public static Set<String> getStaticNames() {
        return staticSymbols;
    }

    public PrintfFunction() {
        super(staticSymbols);
        addDefaultParam("format", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
        setFormatStringParamIndex(0);
    }
}

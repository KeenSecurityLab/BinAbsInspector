package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * int snprintf( char * str, size_t size, const char * format, ... )
 */
public class SnprintfFunction extends VarArgsFunctionBase {

    private static final Set<String> staticSymbols = Set.of("snprintf");

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    public SnprintfFunction() {
        super(staticSymbols);
        addDefaultParam("str", PointerDataType.dataType);
        addDefaultParam("size", IntegerDataType.dataType);
        addDefaultParam("format", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
        setFormatStringParamIndex(2);
    }

}

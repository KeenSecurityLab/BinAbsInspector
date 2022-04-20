package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * int fprintf(FILE *stream, const char *format, ...)
 */
public class FprintfFunction extends VarArgsFunctionBase {

    private static final Set<String> staticSymbols = Set.of("fprintf");

    public FprintfFunction() {
        super(staticSymbols);
        addDefaultParam("stream", PointerDataType.dataType);
        addDefaultParam("format", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
        setFormatStringParamIndex(1);
    }
}

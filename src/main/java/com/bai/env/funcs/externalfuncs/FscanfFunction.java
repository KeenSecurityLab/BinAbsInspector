package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * int fscanf(FILE *stream, const char *format, ...)
 */
public class FscanfFunction extends InputVarArgsFunctionBase {

    private static final Set<String> staticNames = Set.of("fscanf", "__isoc99_fscanf");

    public static Set<String> getStaticSymbols() {
        return staticNames;
    }

    public FscanfFunction() {
        super(staticNames);
        addDefaultParam("stream", PointerDataType.dataType);
        addDefaultParam("format", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
        setFormatStringParamIndex(1);
    }
}

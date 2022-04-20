package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * int sprintf(char *str, const char *format, ...)
 */
public class SprintfFunction extends VarArgsFunctionBase {

    private static final Set<String> staticSymobls = Set.of("sprintf");

    public SprintfFunction() {
        super(staticSymobls);
        addDefaultParam("str", PointerDataType.dataType);
        addDefaultParam("format", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
        setFormatStringParamIndex(1);
    }
}

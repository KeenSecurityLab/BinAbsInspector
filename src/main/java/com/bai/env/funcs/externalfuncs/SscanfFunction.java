package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * int sscanf(const char *s, const char *format, ...)
 */
public class SscanfFunction extends  InputVarArgsFunctionBase {
    private static final Set<String> staticSymbols = Set.of("sscanf");

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    public SscanfFunction() {
        super(staticSymbols);
        addDefaultParam("s", PointerDataType.dataType);
        addDefaultParam("format", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
        setFormatStringParamIndex(1);
    }
}

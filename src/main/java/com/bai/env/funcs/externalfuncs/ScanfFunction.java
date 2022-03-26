package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * int scanf(const char *format, ...)
 */
public class ScanfFunction extends InputVarArgsFunctionBase {
    private static final Set<String> staticSymbols = Set.of("scanf", "__isoc99_scanf");

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    public ScanfFunction() {
        super(staticSymbols);
        addDefaultParam("format", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
        setFormatStringParamIndex(0);
    }
}

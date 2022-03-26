package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * char *gets(char *str)
 */
public class GetsFunction extends InputFunctionBase {

    private static final Set<String> staticSymbols = Set.of("gets");

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    public GetsFunction() {
        // char *gets(char *s)
        super(staticSymbols);
        addDefaultParam("s", PointerDataType.dataType);
        setTaintedBufParamIndex(0);
        setReturnType(PointerDataType.dataType);
        setReturnNewTaint(false);
    }
}
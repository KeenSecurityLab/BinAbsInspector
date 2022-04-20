package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * char *fgets(char *s, int size, FILE *stream)
 */
public class FgetsFunction extends InputFunctionBase {

    private static final Set<String> staticSymbols = Set.of("fgets");

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    public FgetsFunction() {
        super(staticSymbols);
        addDefaultParam("s", PointerDataType.dataType);
        addDefaultParam("size", IntegerDataType.dataType);
        addDefaultParam("stream", PointerDataType.dataType);
        setTaintedBufParamIndex(0);
        setReturnType(PointerDataType.dataType);
        setReturnNewTaint(false);
    }
}

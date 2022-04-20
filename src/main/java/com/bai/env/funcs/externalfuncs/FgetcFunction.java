package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * int fgetc(FILE *stream)
 */
public class FgetcFunction extends InputFunctionBase {

    private static final Set<String> staticSymbols = Set.of("fgetc");

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    public FgetcFunction() {
        super(staticSymbols);
        addDefaultParam("stream", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
        setReturnNewTaint(true);

    }
}

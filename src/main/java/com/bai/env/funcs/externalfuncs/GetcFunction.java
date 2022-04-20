package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * int getc(FILE *stream)
 */
public class GetcFunction extends InputFunctionBase {

    private static final Set<String> staticSymbols = Set.of("getc");

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    public GetcFunction() {
        super(staticSymbols);
        addDefaultParam("stream", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
        setReturnNewTaint(true);
    }
}
package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * ssize_t read(int fd, void *buf, size_t count);
 */
public class ReadFunction extends InputFunctionBase {

    private static final Set<String> staticSymbols = Set.of("read");

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    public ReadFunction() {
        super(staticSymbols);
        addDefaultParam("fd", IntegerDataType.dataType);
        addDefaultParam("buf", PointerDataType.dataType);
        addDefaultParam("count", IntegerDataType.dataType);
        setTaintedBufParamIndex(1);
        setReturnType(IntegerDataType.dataType);
        setReturnNewTaint(false);
    }
}

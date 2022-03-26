package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import java.util.Set;

/**
 * ssize_t recv(int sockfd, void *buf, size_t len, int flags)
 */
public class RecvFunction extends InputFunctionBase {

    private static final Set<String> staticSymbols = Set.of("recv");

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    public RecvFunction() {
        super(staticSymbols);
        addDefaultParam("sockfd", IntegerDataType.dataType);
        addDefaultParam("buf", PointerDataType.dataType);
        addDefaultParam("len", IntegerDataType.dataType);
        addDefaultParam("flags", IntegerDataType.dataType);
        setTaintedBufParamIndex(1);
        setReturnType(IntegerDataType.dataType);
        setReturnNewTaint(false);
    }
}

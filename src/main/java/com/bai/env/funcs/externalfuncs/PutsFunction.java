package com.bai.env.funcs.externalfuncs;

import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.KSet;
import java.util.Set;

/**
 * int puts(char *str)
 */
public class PutsFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("puts");

    public PutsFunction() {
        super(staticSymbols);
        addDefaultParam("puts", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        if (retALoc == null) {
            return;
        }
        inOutEnv.set(retALoc, KSet.getTop(), true);
    }
}

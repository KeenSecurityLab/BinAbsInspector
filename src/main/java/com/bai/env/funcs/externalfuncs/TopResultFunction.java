package com.bai.env.funcs.externalfuncs;


import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Set;

/**
 * This is a model for roughly mocking external functions which we don't care about result for now.
 * For example: for statement `if (strncmp(str, "test")) {}`,
 * we assume the return value of "strncmp" could be anything (TOP), so that we can analyze both paths.
 */
public class TopResultFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("strncmp", "strcmp");

    public TopResultFunction() {
        super(staticSymbols);
    }

    @Override
    public void defineDefaultSignature(Function callFunction) {
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

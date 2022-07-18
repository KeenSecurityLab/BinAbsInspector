package com.bai.env.funcs.externalfuncs;

import static com.bai.util.Utils.getAddress;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.TaintMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Set;

/**
 * int rand(void)
 */
public class RandFunction extends  ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("rand");

    public RandFunction() {
        super(staticSymbols);
        setReturnType(IntegerDataType.dataType);
    }

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        if (retALoc == null) {
            return;
        }
        Address callAddress = getAddress(pcode);
        long taints = TaintMap.getTaints(callAddress, context, callFunc);
        inOutEnv.set(retALoc, KSet.getTop(taints), true);
    }

}

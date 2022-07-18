package com.bai.env.funcs.externalfuncs;

import static com.bai.util.Utils.getAddress;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.TaintMap;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Set;


/**
 * char *getenv(const char *name)
 */
public class GetenvFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("getenv");

    public GetenvFunction() {
        super(staticSymbols);
        addDefaultParam("name", PointerDataType.dataType);
        setReturnType(PointerDataType.dataType);
    }

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

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

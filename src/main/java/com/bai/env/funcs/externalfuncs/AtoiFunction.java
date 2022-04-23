package com.bai.env.funcs.externalfuncs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Set;
import org.javimmutable.collections.JImmutableMap.Entry;

/**
 * int atoi(const char *nptr)
 * long atol(const char *nptr)
 * long long atoll(const char *nptr)
 * long long atoq(const char *nptr)
 */
public class AtoiFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("atoi", "atol", "atoll", "atoq");

    public AtoiFunction() {
        super(staticSymbols);
        addDefaultParam("str", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        if (retALoc == null) {
            return;
        }
        KSet ptrKSet = getParamKSet(callFunc, 0, inOutEnv);
        if (ptrKSet.isTop()) {
            inOutEnv.set(retALoc, ptrKSet, true);
            return;
        }
        long taints = 0;
        for (AbsVal ptr: ptrKSet) {
            ALoc tmp = ALoc.getALoc(ptr.getRegion(), ptr.getValue(), 1);
            Entry<ALoc, KSet> entry = inOutEnv.getOverlapEntry(tmp);
            if (entry != null && entry.getValue().isTop() && entry.getValue().isTaint()) {
                taints |= entry.getValue().getTaints();
            }
        }
        inOutEnv.set(retALoc, KSet.getTop(taints), true);
    }
}

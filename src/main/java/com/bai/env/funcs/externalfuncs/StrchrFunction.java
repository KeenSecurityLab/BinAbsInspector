package com.bai.env.funcs.externalfuncs;


import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.util.StringUtils;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Set;


/**
 * char *strchr(const char *str, int c)
 */
public class StrchrFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("strchr");

    public StrchrFunction() {
        super(staticSymbols);
        addDefaultParam("str", PointerDataType.dataType);
        addDefaultParam("int", IntegerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
    }

    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        KSet strPtrKSet = getParamKSet(callFunc, 0, inOutEnv);
        KSet cKSet = getParamKSet(callFunc, 1, inOutEnv);
        if (!strPtrKSet.isNormal() || !cKSet.isNormal()) {
            long taints = strPtrKSet.getTaints() | cKSet.getTaints();
            inOutEnv.set(retALoc, KSet.getTop(taints), true);
            return;
        }

        KSet resKSet = new KSet(retALoc.getLen() * 8);
        for (AbsVal ptr : strPtrKSet) {
            for (AbsVal c: cKSet) {
                if (c.getValue() < Character.MIN_VALUE ||  c.getValue() > Character.MAX_VALUE) {
                    continue;
                }
                char chr = (char) c.getValue();
                int idx = StringUtils.indexOf(ptr, chr, inOutEnv);
                if (idx == -1) {
                    continue;
                }
                resKSet = resKSet.insert(new AbsVal(ptr.getValue() + idx));
            }
        }
        inOutEnv.set(retALoc, resKSet, true);
    }
}

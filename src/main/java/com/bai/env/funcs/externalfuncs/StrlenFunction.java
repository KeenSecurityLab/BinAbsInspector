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
import com.bai.util.StringUtils;
import java.util.Set;


/**
 * size_t strlen(const char *str)
 */
public class StrlenFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("strlen", "wcslen");

    public StrlenFunction() {
        super(staticSymbols);
        addDefaultParam("str", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
    }

    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        KSet strPtrKSet = getParamKSet(callFunc, 0, inOutEnv);
        if (!strPtrKSet.isNormal()) {
            return;
        }

        KSet resKSet = new KSet(retALoc.getLen() * 8);
        for (AbsVal ptr : strPtrKSet) {
            int len = StringUtils.strlen(ptr, inOutEnv);
            resKSet = resKSet.insert(new AbsVal(len));
        }
        inOutEnv.set(retALoc, resKSet, true);
    }
}

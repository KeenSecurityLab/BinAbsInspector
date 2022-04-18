package com.bai.env.funcs.externalfuncs;

import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Set;

public class LibcStartMainFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("__libc_start_main");

    public LibcStartMainFunction() {
        super(staticSymbols);
        addDefaultParam("main", PointerDataType.dataType);
        addDefaultParam("argc", IntegerDataType.dataType);
        addDefaultParam("argv", PointerDataType.dataType);
        setReturnType(IntegerDataType.dataType);
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        KSet mainPtrKSet = getParamKSet(callFunc, 0, inOutEnv);
        if (!mainPtrKSet.isNormal()) {
            Logging.error("Failed to get Main function pointer.");
            return;
        }
        if (!mainPtrKSet.isSingleton()) {
            Logging.error("Multiple Main function pointer found.");
            return;
        }
        AbsVal mainPtr = mainPtrKSet.getInnerSet().iterator().next();
        Address mainAddress = GlobalState.flatAPI.toAddr(mainPtr.getValue());
        Function mainFunc = GlobalState.flatAPI.getFunctionAt(mainAddress);
        if (mainFunc == null) {
            Logging.error("Failed to get Main function.");
            return;
        }
        Context mainContext = Context.getContext(context, Utils.getAddress(pcode), mainFunc);
        mainContext.initContext(inOutEnv, true);
        Context.pushActive(mainContext);
    }
}

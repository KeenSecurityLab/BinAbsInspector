package com.bai.env.funcs.externalfuncs;

import static com.bai.util.Utils.getAddress;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.TaintMap;
import com.bai.env.region.Reg;
import com.bai.util.GlobalState;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import com.bai.util.Logging;
import java.util.Set;

/**
 * The base class of input function model with varargs.
 */
public abstract class InputVarArgsFunctionBase extends VarArgsFunctionBase {

    protected InputVarArgsFunctionBase(Set<String> symbols) {
        super(symbols);
    }

    private void taintVarArgs(PcodeOp pcodeOp, AbsEnv inOutEnv, Function callFunc, long newTaints) {
        PrototypeModel callingConvention = callFunc.getCallingConvention();
        if (callingConvention == null) {
            callingConvention = GlobalState.currentProgram.getCompilerSpec().getDefaultCallingConvention();
        }
        if (functionDefinition == null) {
            Logging.error("Could not find signature for " + callFunc.getName() + " at " + Utils.getAddress(pcodeOp));
            return;
        }
        ParameterDefinition[] params = functionDefinition.getArguments();
        for (int i = defaultParameters.size(); i < params.length; i++) {
            VariableStorage variableStorage = callingConvention.getArgLocation(i, null,
                    params[i].getDataType(), GlobalState.currentProgram);

            Logging.debug("Tainting var storage " + variableStorage.toString());
            if (variableStorage.isUnassignedStorage()) {
                Logging.debug("Skipping unassigned var storage " + variableStorage);
                continue;
            }
            Logging.debug("Has " + variableStorage.getVarnodeCount() + " varnodes");
            Varnode varnode = variableStorage.getLastVarnode();
            Logging.debug("Tainting var node " + varnode);
            taintVarnodeWithTop(varnode, inOutEnv, newTaints);
        }
    }

    private void taintVarnodeWithTop(Varnode varnode, AbsEnv absEnv, long taints) {
        KSet topKSet = KSet.getTop(taints);
        if (varnode.getAddress().isStackAddress()) {
            KSet spKSet = absEnv.get(ALoc.getSPALoc());
            if (spKSet.isTop()) {
                return;
            }
            for (AbsVal spAbsVal : spKSet) {
                ALoc stackALoc = ALoc.getALoc(spAbsVal.getRegion(), spAbsVal.getValue() + varnode.getOffset(),
                        varnode.getSize());
                absEnv.set(stackALoc, topKSet, true);
            }
        } else if (varnode.isRegister()) {
            ALoc regALoc = ALoc.getALoc(Reg.getInstance(), varnode.getOffset(),
                    GlobalState.arch.getDefaultPointerSize());
            KSet varPtrKSet = absEnv.get(regALoc);
            if (!varPtrKSet.isNormal()) {
                absEnv.set(regALoc, topKSet, true);
            } else {
                for (AbsVal bufPtr : varPtrKSet) {
                    Utils.taintBufWithTop(absEnv, bufPtr, taints);
                }
            }
        }
    }

    public void invoke(PcodeOp pcodeOp, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        super.invoke(pcodeOp, inOutEnv, tmpEnv, context, callFunc);
        Address callAddress = getAddress(pcodeOp);
        long newTaints = TaintMap.getTaints(callAddress, context, callFunc);
        taintVarArgs(pcodeOp, inOutEnv, callFunc, newTaints);
    }
}

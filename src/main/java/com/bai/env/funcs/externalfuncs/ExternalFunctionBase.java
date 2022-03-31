package com.bai.env.funcs.externalfuncs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Reg;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.PrototypeModel;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * The base class of all external function models.
 */
public abstract class ExternalFunctionBase {

    public ExternalFunctionBase(Set<String> symbols) {
        this.symbols = symbols;
    }

    protected Set<String> symbols;

    protected ArrayList<ParameterDefinitionImpl> defaultParameters = new ArrayList<>();

    protected DataType returnType;

    /**
     * Invoke the function model.
     * Only use in PcodeVisitor.
     * @param pcode the pcode.
     * @param inOutEnv the inOut AbsEnv.
     * @param tmpEnv the temp AbsEnv.
     * @param context the Context.
     * @param calleeFunc the callee Function.
     */
    public abstract void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc);

    /**
     * @hidden
     * @param calleeFunc
     */
    public void defineDefaultSignature(Function calleeFunc) {
        if (calleeFunc.getParameters().length == defaultParameters.size()) {
            return;
        }
        try {
            final int tid = GlobalState.currentProgram.startTransaction("define signature");
            FunctionDefinitionDataType funcSignature = new FunctionDefinitionDataType(calleeFunc.getName());
            funcSignature.setArguments(defaultParameters.toArray(new ParameterDefinition[0]));
            funcSignature.setReturnType(returnType);
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                    calleeFunc.getEntryPoint(),
                    funcSignature,
                    SourceType.USER_DEFINED
            );
            cmd.applyTo(GlobalState.currentProgram, TaskMonitor.DUMMY);
            GlobalState.currentProgram.endTransaction(tid, true);
        } catch (Exception e) {
            Logging.warn("Fail to define signature for " + calleeFunc);
            e.printStackTrace();
        }
    }

    /**
     * Get default parameters.
     * @return a list of default parameters.
     */
    public List<ParameterDefinitionImpl> getDefaultParameters() {
        return defaultParameters;
    }

    /**
     * @hidden
     * Get a list of default parameter indexes which in PointerDataType.
     * Only use for checking CWE476 (Null Pointer Deference).
     * @return a list of indexes.
     */
    public List<Integer> getPointerParameterIndexes() {
        List<Integer> res = new ArrayList<>();
        for (int i = 0; i < defaultParameters.size(); i++) {
            if (defaultParameters.get(i).getDataType().equals(PointerDataType.dataType)) {
                res.add(i);
            }
        }
        return res;
    }

    /**
     * Add a default parameter for the function model.
     * @param name the parameter name.
     * @param type the parameter type.
     */
    protected void addDefaultParam(String name, DataType type) {
        ParameterDefinitionImpl param = new ParameterDefinitionImpl(name, type, name);
        defaultParameters.add(param);
    }

    /**
     * Set the return type for the function model
     * @param returnType the return type.
     */
    protected void setReturnType(DataType returnType) {
        this.returnType = returnType;
    }

    /**
     * Get symbols of the function model.
     * @return a set of symbol strings.
     */
    public Set<String> getSymbols() {
        return symbols;
    }

    /**
     * Get ALocs of the function parameter.
     * Only use this in function models.
     *
     * @param function the function.
     * @param paramIdx the parameter index.
     * @param absEnv the AbsEnv.
     * @return a list of ALocs.
     */
    public static List<ALoc> getParamALocs(Function function, int paramIdx, AbsEnv absEnv) {
        List<ALoc> res = new ArrayList<>();
        Parameter parameter = function.getParameter(paramIdx);
        if (parameter == null) {
            return res;
        }
        Varnode varnode = parameter.getLastStorageVarnode();
        if (varnode == null) {
            return res;
        }
        if (varnode.getAddress().isStackAddress()) {
            res = ALoc.getStackALocs(varnode, absEnv);
        } else {
            res.add(ALoc.getALoc(varnode));
        }
        return res;
    }

    /**
     * Get KSet of corresponding parameter.
     * Only use this in function models.
     * @param function the function.
     * @param paramIdx the parameter index.
     * @param absEnv the AbsEnv.
     * @return the KSet.
     */
    public static KSet getParamKSet(Function function, int paramIdx, AbsEnv absEnv) {
        KSet res = null;
        for (ALoc aLoc : getParamALocs(function, paramIdx, absEnv)) {
            KSet tmp = absEnv.get(aLoc);
            if (res == null) {
                res = tmp;
            } else {
                KSet union = res.join(tmp);
                res = (union == null) ? res : union;
            }
        }
        return res == null ? KSet.getBot(GlobalState.arch.getDefaultPointerSize() * 8) : res;
    }

    /**
     * Get ALocs of a VarArg parameter.
     * Can be used in function model and online checker.
     *
     * @param function the function.
     * @param signature the signature.
     * @param paramIdx the parameter index.
     * @param absEnv the AbsEnv.
     * @return a list of ALocs.
     */
    public static List<ALoc> getVarArgsParamALoc(Function function, FunctionDefinition signature, int paramIdx,
            AbsEnv absEnv) {
        List<ALoc> res = new ArrayList<>();
        if (paramIdx >= signature.getArguments().length) {
            Logging.error("Fail to get ALoc for " + function + " at " + Utils.getOrdinal(paramIdx) + " argument.");
            return res;
        }
        ParameterDefinition parameterDefinition = signature.getArguments()[paramIdx];
        PrototypeModel callingConvention = function.getCallingConvention();
        if (callingConvention == null) {
            callingConvention = GlobalState.currentProgram.getFunctionManager().getDefaultCallingConvention();
        }
        VariableStorage variableStorage = callingConvention.getArgLocation(paramIdx, null,
                parameterDefinition.getDataType(), GlobalState.currentProgram);
        Varnode varnode = variableStorage.getLastVarnode();
        if (varnode.getAddress().isStackAddress()) {
            res = ALoc.getStackALocs(varnode, absEnv);
        } else {
            res.add(ALoc.getALoc(varnode));
        }
        return res;
    }

    /**
     * Get ALocs of a VarArg parameter.
     * Can be used in function model and online checker.
     *
     * @param function the function.
     * @param signature the signature.
     * @param paramIdx the signature.
     * @param absEnv the parameter index.
     * @return the KSet.
     */
    public static KSet getVarArgsParamKSet(Function function, FunctionDefinition signature, int paramIdx,
            AbsEnv absEnv) {
        KSet res = null;
        for (ALoc aLoc : getVarArgsParamALoc(function, signature, paramIdx, absEnv)) {
            KSet tmp = absEnv.get(aLoc);
            if (res == null) {
                res = tmp;
            } else {
                KSet union = res.join(tmp);
                res = (union == null) ? res : union;
            }
        }
        return res == null ? KSet.getBot(GlobalState.arch.getDefaultPointerSize() * 8) : res;
    }

    /**
     * Get ALoc of a function return register with check.
     * @param function  the function.
     * @param useDefaultPointerSize return ALoc with default pointer size if true,
     *      Ghidra will return size of 1 when it fails to detect return type.
     * @return the ALoc.
     */
    public static ALoc getReturnALoc(Function function, boolean useDefaultPointerSize) {
        Optional<Parameter> parameterOptional = Optional.of(function.getReturn());
        ALoc aLoc;
        if (useDefaultPointerSize) {
            aLoc = parameterOptional.map(Parameter::getRegister)
                    .map(Register::getOffset)
                    .map((offset) -> ALoc.getALoc(Reg.getInstance(), offset, GlobalState.arch.getDefaultPointerSize()))
                    .orElse(null);
        } else {
            aLoc = parameterOptional.map(Parameter::getFirstStorageVarnode)
                    .map(ALoc::getALoc)
                    .orElse(null);

        }
        if (aLoc == null) {
            Logging.error("Failed to get ALoc for return of " + function);
        }
        return aLoc;
    }
}

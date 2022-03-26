package com.bai.env.funcs.stdfuncs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

/** The base class of all cpp std function models
 * @param <T>
 */
public abstract class CppStdModelBase<T> {

    static class Signature {

        private List<ParameterDefinitionImpl> defaultParameters;
        private DataType returnType;

        public Signature(List<ParameterDefinitionImpl> defaultParameters, DataType returnType) {
            this.defaultParameters = defaultParameters;
            this.returnType = returnType;
        }
    }

    protected HashMap<ALoc, T> pool = new HashMap<>();

    protected HashMap<String, Signature> signatureHashMap = new HashMap<>();

    protected Set<String> symbols;

    protected CppStdModelBase(Set<String> symbols) {
        this.symbols = symbols;
    }

    /**
     * Reset the container.
     */
    public void resetPool() {
        pool.clear();
    }

    /**
     * @hidden
     * Get a new container. Use for constructor.
     * @return
     */
    protected abstract T getNewContainer();

    /**
     * @hidden
     * Get a new container from the old one. Use for copy constructor.
     * @param other
     * @return
     */
    protected abstract T getNewContainer(T other);

    /**
     * Get container initialize at given ALoc.
     * @param aLoc the ALoc
     * @return the container.
     */
    protected T getContainer(ALoc aLoc) {
        T container = pool.get(aLoc);
        if (container != null) {
            return container;
        }
        Logging.debug("Create container for " + aLoc);
        container = getNewContainer();
        pool.put(aLoc, container);
        return container;
    }

    /**
     * Modeling constructor.
     * @param pcode the pcode.
     * @param inOutEnv the inOut AbsEnv.
     * @param tmpEnv the temp AbsEnv.
     * @param context the Context.
     * @param calleeFunc the callee function.
     */
    protected void invokeConstructor(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context,
            Function calleeFunc) {
        if (calleeFunc.getParameterCount() != 1) {
            Logging.error("Wrong parameter for: " + calleeFunc);
            return;
        }
        KSet ptrKSet = getParamKSet(calleeFunc, 0, inOutEnv);
        if (!ptrKSet.isNormal()) {
            return;
        }
        for (AbsVal ptrAbsVal : ptrKSet) {
            if (ptrAbsVal.isBigVal()) {
                continue;
            }
            ALoc ptrALoc = ALoc.getALoc(ptrAbsVal.getRegion(), ptrAbsVal.getValue(),
                    GlobalState.arch.getDefaultPointerSize());
            getContainer(ptrALoc);
        }
    }

    /**
     * Modeling copy constructor.
     * @param pcode the pcode.
     * @param inOutEnv the inOut AbsEnv.
     * @param tmpEnv the temp AbsEnv.
     * @param context the Context.
     * @param calleeFunc the callee function.
     */
    protected void invokeCopyConstructor(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context,
            Function calleeFunc) {
        if (calleeFunc.getParameterCount() != 2) {
            Logging.error("Wrong parameter for: " + calleeFunc);
            return;
        }
        KSet otherKSet = getParamKSet(calleeFunc, 0, inOutEnv);
        KSet thisKSet = getParamKSet(calleeFunc, 1, inOutEnv);
        if (!otherKSet.isNormal() || !thisKSet.isNormal()) {
            return;
        }
        for (AbsVal thisPtrAbsVal : thisKSet) {
            for (AbsVal otherPtrAbsVal : otherKSet) {
                ALoc thisPtrALoc = ALoc.getALoc(thisPtrAbsVal.getRegion(), thisPtrAbsVal.getValue(),
                        GlobalState.arch.getDefaultPointerSize());
                ALoc otherPtrALoc = ALoc.getALoc(otherPtrAbsVal.getRegion(), otherPtrAbsVal.getValue(),
                        GlobalState.arch.getDefaultPointerSize());
                T thisContainer = getContainer(thisPtrALoc);
                T otherContainer = getNewContainer(thisContainer);
                pool.put(otherPtrALoc, otherContainer);
            }
        }
    }

    /**
     * Modeling destructor
     * @param pcode the pcode.
     * @param inOutEnv the inOut AbsEnv.
     * @param tmpEnv the temp AbsEnv.
     * @param context the Context.
     * @param calleeFunc the callee function.
     */
    protected void invokeDestructor(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context,
            Function calleeFunc) {
        if (calleeFunc.getParameterCount() != 1) {
            Logging.error("Wrong parameter for: " + calleeFunc);
            return;
        }
        KSet thisKSet = getParamKSet(calleeFunc, 0, inOutEnv);
        if (!thisKSet.isNormal()) {
            return;
        }
        for (AbsVal thisPtrAbsVal : thisKSet) {
            ALoc thisPtrALoc = ALoc.getALoc(thisPtrAbsVal.getRegion(), thisPtrAbsVal.getValue(),
                    GlobalState.arch.getDefaultPointerSize());
            pool.remove(thisPtrALoc);
        }
    }

    /**
     * Invoke the function model.
     * @param pcode the pcode.
     * @param inOutEnv the inOut AbsEnv.
     * @param tmpEnv the temp AbsEnv.
     * @param context the Context.
     * @param calleeFunc the callee Function.
     */
    public abstract void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function calleeFunc);

    public static KSet getParamKSet(Function function, int paramIdx, AbsEnv absEnv) {
        return ExternalFunctionBase.getParamKSet(function, paramIdx, absEnv);
    }

    public static ALoc getReturnALoc(Function function, boolean useDefaultPointerSize) {
        return ExternalFunctionBase.getReturnALoc(function, useDefaultPointerSize);
    }

    /**
     * Add default signature.
     * @param functionName the function name.
     * @param params a list of parameters.
     * @param returnType the return type.
     */
    public void addDefaultSignature(String functionName, List<ParameterDefinitionImpl> params, DataType returnType) {
        //FIXME: Handle polymorphism signature
        Signature signature = new Signature(params, returnType);
        signatureHashMap.put(functionName, signature);
    }

    /**
     * @hidden
     * Only use in PcodeVisitor.
     * @param callee the callee function.
     */
    public void defineDefaultSignature(Function callee) {
        Signature signature = signatureHashMap.get(callee.getName());
        if (signature == null || signature.defaultParameters.size() == callee.getParameterCount()) {
            return;
        }
        try {
            final int tid = GlobalState.currentProgram.startTransaction("define signature");
            FunctionDefinitionDataType funcSignature = new FunctionDefinitionDataType(callee.getName());
            funcSignature.setArguments(signature.defaultParameters.toArray(new ParameterDefinition[0]));
            funcSignature.setReturnType(signature.returnType);
            ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                    callee.getEntryPoint(),
                    funcSignature,
                    SourceType.USER_DEFINED
            );
            cmd.applyTo(GlobalState.currentProgram, TaskMonitor.DUMMY);
            GlobalState.currentProgram.endTransaction(tid, true);
        } catch (Exception e) {
            Logging.warn("Fail to define signature for " + callee);
            e.printStackTrace();
        }
    }

    public Set<String> getSymbols() {
        return symbols;
    }
}
package com.bai.env.funcs.stdfuncs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * std::vector
 */
public class VectorModel extends CppStdModelBase<ArrayList<KSet>> {

    private static final Set<String> staticSymbols = Set.of("vector");

    public VectorModel() {
        super(staticSymbols);
        addDefaultSignature("end",
                List.of(new ParameterDefinitionImpl("this", PointerDataType.dataType, "this")),
                PointerDataType.dataType);
    }

    @Override
    protected ArrayList<KSet> getNewContainer() {
        return new ArrayList<>();
    }

    @Override
    protected ArrayList<KSet> getNewContainer(ArrayList<KSet> other) {
        return new ArrayList<>(other);
    }

    private void end(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        if (callFunc.getParameterCount() != 1) {
            Logging.error("Wrong parameter for: " + callFunc);
            return;
        }
        ALoc retALoc = getReturnALoc(callFunc, true);
        if (retALoc == null) {
            return;
        }
        // return TOP for all iterator because we perform field-insensitive analysis
        inOutEnv.set(retALoc, KSet.getTop(), true);
    }

    private void insert(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        if (callFunc.getParameterCount() != 4) {
            Logging.error("Wrong parameter for: " + callFunc);
            return;
        }
        KSet thisKSet = getParamKSet(callFunc, 0, inOutEnv);
        KSet iteratorKSet = getParamKSet(callFunc, 1, inOutEnv);
        KSet countKSet = getParamKSet(callFunc, 2, inOutEnv);
        KSet valueKSet = getParamKSet(callFunc, 3, inOutEnv);

        if (!iteratorKSet.isTop()) {
            Logging.warn("Iterator KSet should be TOP, because we are performing field-insensitive analysis.");
            return;
        }

        long count = 0;
        if (countKSet.isNormal()) {
            for (AbsVal countAbsVal : countKSet) {
                if (countAbsVal.isBigVal()) {
                    continue;
                }
                count = Long.max(countAbsVal.getValue(), count);
            }
        }

        if (!thisKSet.isNormal()) {
            return;
        }
        for (AbsVal thisPtrAbsVal : thisKSet) {
            ALoc thisPtrALoc = ALoc.getALoc(thisPtrAbsVal.getRegion(), thisPtrAbsVal.getValue(),
                    GlobalState.arch.getDefaultPointerSize());
            ArrayList<KSet> thisContainer = getContainer(thisPtrALoc);
            for (int i = 0; i < count; i++) {
                if (thisContainer.size() == 0) {
                    thisContainer.add(valueKSet);
                    continue;
                }
                for (int j = 0; j < thisContainer.size(); j++) {
                    KSet old = thisContainer.get(j);
                    KSet updated = old.join(valueKSet);
                    if (updated != null) {
                        thisContainer.set(j, updated);
                    }
                }
            }
        }
    }

    private void subscript(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        if (callFunc.getParameterCount() != 2) {
            Logging.error("Wrong parameter for: " + callFunc);
            return;
        }
        ALoc retALoc = getReturnALoc(callFunc, true);
        if (retALoc == null) {
            return;
        }
        KSet thisKSet = getParamKSet(callFunc, 0, inOutEnv);
        KSet indexKSet = getParamKSet(callFunc, 1, inOutEnv);
        if (!thisKSet.isNormal()) {
            return;
        }

        KSet resKSet = new KSet(GlobalState.arch.getDefaultPointerSize() * 8);
        for (AbsVal thisPtrAbsVal : thisKSet) {
            ALoc thisPtrALoc = ALoc.getALoc(thisPtrAbsVal.getRegion(), thisPtrAbsVal.getValue(),
                    GlobalState.arch.getDefaultPointerSize());
            ArrayList<KSet> thisContainer = getContainer(thisPtrALoc);
            // try to find value at given idx
            if (indexKSet.isNormal()) {
                for (AbsVal idxAbsVal : indexKSet) {
                    if (idxAbsVal.isBigVal()) {
                        continue;
                    }
                    long idx = idxAbsVal.getValue();
                    if (idx > thisContainer.size() - 1) {
                        continue;
                    }
                    KSet oldKSet = thisContainer.get((int) idx);
                    if (oldKSet != null) {
                        KSet tmp = resKSet.join(oldKSet);
                        resKSet = (tmp == null) ? resKSet : tmp;
                    }
                }
            }
            // joined all value and return if no value at given idx
            if (resKSet.isBot()) {
                for (KSet value : thisContainer) {
                    KSet tmp = resKSet.join(value);
                    resKSet = (tmp == null) ? resKSet : tmp;
                }
            }
        }
        inOutEnv.set(retALoc, resKSet, true);
    }

    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        Logging.debug("Invoke std::vector::" + callFunc.getName());
        switch (callFunc.getName()) {
            case "vector":
                if (callFunc.getParameterCount() == 1) {
                    invokeConstructor(pcode, inOutEnv, tmpEnv, context, callFunc);
                } else if (callFunc.getParameterCount() == 2) {
                    invokeCopyConstructor(pcode, inOutEnv, tmpEnv, context, callFunc);
                }
                break;
            case "end":
                end(pcode, inOutEnv, tmpEnv, context, callFunc);
                break;
            case "insert":
                insert(pcode, inOutEnv, tmpEnv, context, callFunc);
                break;
            case "operator[]":
                subscript(pcode, inOutEnv, tmpEnv, context, callFunc);
                break;
            case "~vector":
                invokeDestructor(pcode, inOutEnv, tmpEnv, context, callFunc);
                break;
            default:
        }
    }

}

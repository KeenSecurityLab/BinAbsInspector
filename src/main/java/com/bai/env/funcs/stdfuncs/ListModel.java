package com.bai.env.funcs.stdfuncs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import java.util.LinkedList;
import java.util.Set;

/**
 * std::list
 */
public class ListModel extends CppStdModelBase<LinkedList<KSet>> {

    private static final Set<String> staticSymbols = Set.of("list");

    public ListModel() {
        super(staticSymbols);
    }

    @Override
    protected LinkedList<KSet> getNewContainer() {
        return new LinkedList<>();
    }

    @Override
    protected LinkedList<KSet> getNewContainer(LinkedList<KSet> other) {
        return new LinkedList<>(other);
    }

    private void pushBack(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        if (callFunc.getParameterCount() != 2) {
            Logging.error("Wrong parameter for: " + callFunc);
            return;
        }
        KSet thisKSet = getParamKSet(callFunc, 0, inOutEnv);
        if (!thisKSet.isNormal()) {
            return;
        }
        KSet elemKSet = getParamKSet(callFunc, 1, inOutEnv);
        for (AbsVal thisPtrAbsVal : thisKSet) {
            ALoc thisPtrALoc = ALoc.getALoc(thisPtrAbsVal.getRegion(), thisPtrAbsVal.getValue(),
                    GlobalState.arch.getDefaultPointerSize());
            LinkedList<KSet> thisContainer = getContainer(thisPtrALoc);
            thisContainer.offer(elemKSet);
        }
    }

    private void back(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        if (callFunc.getParameterCount() != 1) {
            Logging.error("Wrong parameter for: " + callFunc);
            return;
        }
        ALoc retALoc = getReturnALoc(callFunc, true);
        if (retALoc == null) {
            return;
        }
        KSet thisKSet = getParamKSet(callFunc, 0, inOutEnv);
        if (!thisKSet.isNormal()) {
            return;
        }
        KSet res = null;
        for (AbsVal thisPtrAbsVal : thisKSet) {
            ALoc thisPtrALoc = ALoc.getALoc(thisPtrAbsVal.getRegion(), thisPtrAbsVal.getValue(),
                    GlobalState.arch.getDefaultPointerSize());
            LinkedList<KSet> thisContainer = getContainer(thisPtrALoc);
            if (!thisContainer.isEmpty()) {
                if (res == null) {
                    res = thisContainer.peekLast();
                } else {
                    KSet union = res.join(thisContainer.peekLast());
                    res = (union == null) ? res : union;
                }
            }
        }
        inOutEnv.set(retALoc, res, true);
    }

    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        Logging.debug("Invoke std::list::" + callFunc.getName());
        switch (callFunc.getName()) {
            case "list":
                if (callFunc.getParameterCount() == 1) {
                    invokeConstructor(pcode, inOutEnv, tmpEnv, context, callFunc);
                } else if (callFunc.getParameterCount() == 2) {
                    invokeCopyConstructor(pcode, inOutEnv, tmpEnv, context, callFunc);
                }
                break;
            case "push_back":
                pushBack(pcode, inOutEnv, tmpEnv, context, callFunc);
                break;
            case "back":
                back(pcode, inOutEnv, tmpEnv, context, callFunc);
                break;
            case "~list":
                invokeDestructor(pcode, inOutEnv, tmpEnv, context, callFunc);
                break;
            default: // fallthrough
        }
    }

}

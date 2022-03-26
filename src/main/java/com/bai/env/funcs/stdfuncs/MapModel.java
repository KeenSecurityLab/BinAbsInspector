package com.bai.env.funcs.stdfuncs;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import com.bai.env.region.Heap;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import java.util.HashMap;
import java.util.Set;

/**
 * std::map
 */
public class MapModel extends CppStdModelBase<HashMap<AbsVal, AbsVal>> {

    private static final Set<String> staticsSymbols = Set.of("map");

    public MapModel() {
        super(staticsSymbols);
    }

    @Override
    protected HashMap<AbsVal, AbsVal> getNewContainer() {
        return new HashMap<>();
    }

    @Override
    protected HashMap<AbsVal, AbsVal> getNewContainer(HashMap<AbsVal, AbsVal> other) {
        return new HashMap<>(other);
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
        if (!thisKSet.isNormal()) {
            return;
        }
        KSet nodeKSet = getParamKSet(callFunc, 1, inOutEnv);
        if (!nodeKSet.isNormal()) {
            Logging.warn("Found multiple node for map. Unimplemented");
            return;
        }
        AbsVal tmp = nodeKSet.iterator().next();
        ALoc tmpALoc = ALoc.getALoc(tmp.getRegion(), tmp.getValue(), GlobalState.arch.getDefaultPointerSize());
        KSet keyKSet = inOutEnv.get(tmpALoc);

        if (keyKSet.isTop()) {
            inOutEnv.set(retALoc, KSet.getTop(keyKSet.getTaints()), true);
            return;
        }

        KSet resKSet = new KSet(GlobalState.arch.getDefaultPointerSize() * 8);
        for (AbsVal thisPtrAbsVal : thisKSet) {
            ALoc thisPtrALoc = ALoc.getALoc(thisPtrAbsVal.getRegion(), thisPtrAbsVal.getValue(),
                    GlobalState.arch.getDefaultPointerSize());
            HashMap<AbsVal, AbsVal> thisContainer = getContainer(thisPtrALoc);
            for (AbsVal key : keyKSet) {
                AbsVal tmpHeap = thisContainer.get(key);
                if (tmpHeap == null) {
                    Heap chunk = Heap.getHeap(Utils.getAddress(pcode), context, true);
                    thisContainer.put(key, AbsVal.getPtr(chunk));
                    tmpHeap = AbsVal.getPtr(chunk);
                }
                resKSet = resKSet.insert(tmpHeap);
            }
        }
        inOutEnv.set(retALoc, resKSet, true);
    }

    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        Logging.debug("Invoke std::map::" + callFunc.getName());
        switch (callFunc.getName()) {
            case "map":
                if (callFunc.getParameterCount() == 1) {
                    invokeConstructor(pcode, inOutEnv, tmpEnv, context, callFunc);
                } else if (callFunc.getParameterCount() == 2) {
                    invokeCopyConstructor(pcode, inOutEnv, tmpEnv, context, callFunc);
                }
                break;
            case "operator[]":
                subscript(pcode, inOutEnv, tmpEnv, context, callFunc);
                break;
            case "~map":
                invokeDestructor(pcode, inOutEnv, tmpEnv, context, callFunc);
                break;
            default: // fallthrough
        }
    }

}

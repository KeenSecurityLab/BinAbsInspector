package com.bai.env.funcs.externalfuncs;

import static com.bai.util.Utils.getAddress;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import com.bai.env.region.RegionBase;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.Set;
import org.javimmutable.collections.JImmutableMap.Entry;
import org.javimmutable.collections.JImmutableSet;

/**
 * void free(void *ptr) <br>
 * delete <br>
 * delete[]
 */
public class FreeFunction extends ExternalFunctionBase {

    private static final Set<String> staticSymbols = Set.of("free", "operator.delete", "operator.delete[]");

    public FreeFunction() {
        super(staticSymbols);
        addDefaultParam("ptr", PointerDataType.dataType);
        setReturnType(VoidDataType.dataType);
    }

    public static Set<String> getStaticSymbols() {
        return staticSymbols;
    }

    /**
     * Delete aLoc of free heap to reduce memory usage.
     * @param absEnv
     * @param ptrKSet
     */
    private void clearHeapALoc(AbsEnv absEnv, KSet ptrKSet) {
        for (AbsVal ptr : ptrKSet) {
            if (!ptr.getRegion().isHeap()) {
                continue;
            }
            for (Entry<ALoc, KSet> entry : absEnv.getEnvMap()) {
                ALoc aLoc = entry.getKey();
                RegionBase r1 = aLoc.getRegion();
                RegionBase r2 = ptr.getRegion();
                if (r1.equals(r2)) {
                    absEnv.set(aLoc, KSet.getBot(aLoc.getLen() * 8), true);
                }
            }
        }
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        KSet argKSet = getParamKSet(callFunc, 0, inOutEnv);
        if (!argKSet.isNormal()) {
            return;
        }
        clearHeapALoc(inOutEnv, argKSet);
        Address freeSiteAddress = getAddress(pcode);
        for (Entry<ALoc, KSet> entry : inOutEnv.getEnvMap()) {
            KSet oldKSet = entry.getValue();
            if (!oldKSet.isNormal()) {
                continue;
            }
            JImmutableSet<AbsVal> intersection = oldKSet.getInnerSet().intersection(argKSet.getInnerSet());
            KSet newKSet = new KSet(oldKSet);
            if (intersection.isEmpty()) {
                continue;
            }
            for (AbsVal oldAbsVal : intersection) {
                if (!oldAbsVal.getRegion().isHeap()) {
                    continue;
                }
                Heap invalidHeap = ((Heap) oldAbsVal.getRegion()).toInvalid(freeSiteAddress);
                newKSet = newKSet.remove(oldAbsVal).insert(AbsVal.getPtr(invalidHeap));
            }
            inOutEnv.set(entry.getKey(), newKSet, true);
        }
    }

}

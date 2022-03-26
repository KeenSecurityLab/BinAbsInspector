package com.bai.env;

import ghidra.program.model.address.Address;
import com.bai.util.GlobalState;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

public class ContextTransitionTable {

    class CallStringComparator implements Comparator<long[]> {

        @Override
        public int compare(long[] callString1, long[] callString2) {
            for (int i = GlobalState.config.getCallStringK() - 1; i >= 0; i--) {
                if (callString1[i] > callString2[i]) {
                    return 1;
                } else if (callString1[i] < callString2[i]) {
                    return -1;
                }
            }
            return 0;
        }
    }

    private Map<Address, TreeSet<long[]>> transitionMap = new HashMap<>();

    public void add(Address callSite, Context currentContext) {
        long[] currentCallString = currentContext.getCallString();
        TreeSet<long[]> callStringSet = transitionMap.get(callSite);
        if (callStringSet == null) {
            callStringSet = new TreeSet<>(new CallStringComparator());
            transitionMap.put(callSite, callStringSet);
        }
        callStringSet.add(currentCallString);
    }

    public Set<long[]> get(Address callSite, long[] callString) {
        long[] lower = callString;
        long[] upper = new long[GlobalState.config.getCallStringK()];
        for (int i = GlobalState.config.getCallStringK() - 1; i >= 0; i--) {
            upper[i] = (callString[i] == 0) ? Long.MAX_VALUE : callString[i];
        }
        TreeSet<long[]> callStringSet = transitionMap.get(callSite);
        if (callStringSet != null) {
            Set<long[]> res = callStringSet.subSet(lower, upper);
            if (!res.isEmpty()) {
                return res;
            }
        }
        return null;
    }

    protected static ContextTransitionTable ctxTrans = new ContextTransitionTable();

    public static ContextTransitionTable getInstance() {
        return ctxTrans;
    }

    public static void reset() {
        ctxTrans.transitionMap.clear();
    }

}

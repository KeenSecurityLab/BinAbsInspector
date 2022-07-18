package com.bai.env;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import com.bai.util.Logging;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 *  Manager which maintains relationship between taint id for taint bitmap in KSet and taint source
 */
public class TaintMap {

    /**
     * Description for each taint source, consisting of a function and its context
     */
    public static class Source {

        private final Address callSite;
        private final Context context;
        private final Function function;

        public Source(Address callSite, Context context, Function function) {
            this.callSite = callSite;
            this.context = context;
            this.function = function;
        }

        public Address getCallSite() {
            return callSite;
        }

        public Context getContext() {
            return context;
        }

        public Function getFunction() {
            return function;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (o == null || getClass() != o.getClass()) {
                return false;
            }
            Source source = (Source) o;
            return Objects.equals(callSite, source.callSite) && Objects.equals(context, source.context)
                    && Objects.equals(function, source.function);
        }

        @Override
        public int hashCode() {
            return Objects.hash(callSite, context, function);
        }
    }

    private static int taintId = 0;
    private static final int MAX_TAINT_CNT = 64;
    private static final Map<Source, Integer> taintSourceToIdMap = new HashMap<>();

    /**
     * Reset the maintained relationship
     */
    public static void reset() {
        taintId = 0;
        taintSourceToIdMap.clear();
    }

    protected static int getTaintId(Address callSite, Context context, Function function) {
        if (taintId >= MAX_TAINT_CNT) {
            Logging.error("Taint id number reach " + MAX_TAINT_CNT
                    + "this may lead to false positive.");
            taintId = taintId % MAX_TAINT_CNT;
        }
        Source src = new Source(callSite, context, function);
        Integer id = taintSourceToIdMap.get(src);
        if (id != null) {
            return id;
        }
        taintSourceToIdMap.put(src, taintId);
        id = taintId;
        taintId++;
        return id;
    }

    /**
     * Get the corresponding taint sources for a given taint bitmap
     * @param taints A given taint bitmap
     * @return A list of corresponding taint sources
     */
    public static List<Source> getTaintSourceList(long taints) {
        ArrayList<Source> res = new ArrayList<>();
        for (Map.Entry<Source, Integer> entry : taintSourceToIdMap.entrySet()) {
            int taintId = entry.getValue();
            if (((taints >>> taintId) & 1) == 1) {
                res.add(entry.getKey());
            }
        }
        return res;
    }

    /**
     * Get a taint bitmap for a taint source consisting of a context and a function
     * @param callSite Call site address of the Function component
     * @param context Context component for a taint source
     * @param function Function component for a taint source
     * @return A taint bitmap for the information of a taint source
     */
    public static long getTaints(Address callSite, Context context, Function function) {
        return 1L << getTaintId(callSite, context, function);
    }

    /**
     * Get a taint bitmap for a taint source with a specific taint id
     * @param taintId Taint id for an existing taint source
     * @return Taint bitmap for the given taint id
     */
    public static long getTaints(int taintId) {
        return 1L << taintId;
    }

}

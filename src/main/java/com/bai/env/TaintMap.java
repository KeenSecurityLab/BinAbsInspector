package com.bai.env;

import ghidra.program.model.listing.Function;
import com.bai.util.Logging;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class TaintMap {

    public static class Source {

        private final Context context;
        private final Function function;

        public Source(Context context, Function function) {
            this.context = context;
            this.function = function;
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
            return Objects.equals(context, source.context) && Objects.equals(function, source.function);
        }

        @Override
        public int hashCode() {
            return Objects.hash(context, function);
        }
    }

    private static int taintId = 0;
    private static final int MAX_TAINT_CNT = 64;
    private static final Map<Source, Integer> taintSourceToIdMap = new HashMap<>();

    public static void reset() {
        taintId = 0;
        taintSourceToIdMap.clear();
    }

    public static int getTaintId(Context context, Function function) {
        if (taintId >= MAX_TAINT_CNT) {
            Logging.error("Taint id number reach " + MAX_TAINT_CNT
                    + "this may lead to false positive.");
            taintId = taintId % MAX_TAINT_CNT;
        }
        Source src = new Source(context, function);
        Integer id = taintSourceToIdMap.get(src);
        if (id != null) {
            return id;
        }
        taintSourceToIdMap.put(src, taintId);
        id = taintId;
        taintId++;
        return id;
    }

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

    public static long getTaints(Context context, Function function) {
        return 1L << getTaintId(context, function);
    }

    public static long getTaints(int taintId) {
        return 1L << taintId;
    }

}

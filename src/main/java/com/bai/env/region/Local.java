package com.bai.env.region;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.listing.Function;

public class Local extends RegionBase { // AR region

    private Function function;
    public static final int DEFAULT_SIZE = 0x2800;
    private static Map<Function, Local> pool = new HashMap<>(); // no duplicates

    private Local(Function function) {
        super(TYPE_LOCAL, DEFAULT_SIZE);
        this.function = function;
    }

    public Function getFunction() {
        return function;
    }

    @Override
    public boolean equals(Object rhs) {
        if (this == rhs) {
            return true;
        }

        if (rhs instanceof Local) {
            Local other = (Local) rhs;
            if (this.function == other.function) {
                return true;
            }
        }

        return false;
    }

    @Override
    public int hashCode() {
        return function.hashCode();
    }

    public static void resetPool() {
        pool.clear();
    }

    public static Local getLocal(Function function) {
        Local oldLocal = pool.get(function);
        if (oldLocal != null) {
            return oldLocal;
        }
        Local newLocal = new Local(function);
        pool.put(function, newLocal);
        return newLocal;
    }

}

package com.bai.env.region;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.listing.Function;

/**
 * Local (stack) region.
 * Represent stack memory for each function.
 */
public class Local extends RegionBase {

    private Function function;

    private static Map<Function, Local> pool = new HashMap<>();

    /**
     * @hidden
     */
    public static final int DEFAULT_SIZE = 0x2800;

    private Local(Function function) {
        super(TYPE_LOCAL, DEFAULT_SIZE);
        this.function = function;
    }

    /**
     * Getter for the function of this Local region
     */
    public Function getFunction() {
        return function;
    }

    /**
     * @hidden
     */
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

    /**
     * @hidden
     */
    @Override
    public int hashCode() {
        return function.hashCode();
    }

    /**
     * @hidden
     */    
    public static void resetPool() {
        pool.clear();
    }

    /**
     * Create a Local region for a given function
     */
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

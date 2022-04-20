package com.bai.env.region;

/**
 * Unique Region.
 * Contains all unique (temporary) variables created by Ghidra.
 */
public class Unique extends RegionBase {
    private Unique() {
        super(TYPE_UNIQUE, -1L);
    }

    /**
     * Get the singleton for Unique region
     */
    public static Unique getInstance() {
        return UniqueInternal.INSTANCE;
    }

    private static class UniqueInternal {
        private static final Unique INSTANCE = new Unique();
    }

    /**
     * @hidden
     */
    @Override
    public boolean equals(Object obj) {
        return obj == this;
    }

    /**
     * @hidden
     */
    @Override
    public int hashCode() {
        return TYPE_UNIQUE;
    }
}

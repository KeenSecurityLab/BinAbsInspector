package com.bai.env.region;

public class Unique extends RegionBase {
    private Unique() {
        super(TYPE_UNIQUE, -1L);
    }

    public static Unique getInstance() {
        return UniqueInternal.INSTANCE;
    }

    private static class UniqueInternal {
        private static final Unique INSTANCE = new Unique();
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this;
    }

    @Override
    public int hashCode() {
        return TYPE_UNIQUE;
    }
}

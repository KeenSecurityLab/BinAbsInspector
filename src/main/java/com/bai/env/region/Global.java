package com.bai.env.region;

public class Global extends RegionBase { // Global region, Singleton

    private Global() {
        super(TYPE_GLOBAL, -1L);
    }

    public static Global getInstance() {
        return GlobalInternal.INSTANCE;
    }

    private static class GlobalInternal {
        private static final Global INSTANCE = new Global();
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this;
    }

    @Override
    public int hashCode() {
        return TYPE_GLOBAL;
    }
}

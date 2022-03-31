package com.bai.env.region;

public class Global extends RegionBase {
    private Global() {
        super(TYPE_GLOBAL, -1L);
    }

    /**
     * Get the singleton Global region
     */
    public static Global getInstance() {
        return GlobalInternal.INSTANCE;
    }

    private static class GlobalInternal {
        private static final Global INSTANCE = new Global();
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
        return TYPE_GLOBAL;
    }
}

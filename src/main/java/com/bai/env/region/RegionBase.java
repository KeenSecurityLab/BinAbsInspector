package com.bai.env.region;

import com.bai.util.GlobalState;

/**
 * The base class of all regions.
 */
public abstract class RegionBase {

    protected int kind;
    protected long size;
    protected long base;

    protected static final int TYPE_GLOBAL = 0; // valid global && const
    protected static final int TYPE_REG = 1;
    protected static final int TYPE_LOCAL = 2; // valid
    protected static final int TYPE_HEAP = 3; // valid
    protected static final int TYPE_UNIQUE = 4;

    private static long accumulator = 0x10000;

    protected RegionBase(int type, long size) {
        this.kind = type;
        this.size = size;
        switch (type) {
            case TYPE_GLOBAL:
            case TYPE_REG:
            case TYPE_UNIQUE:
                this.base = 0;
                break;
            case TYPE_LOCAL:
                this.base = getBase(size) + size;
                break;
            case TYPE_HEAP:
                this.base = getBase(size);
                break;
            default:
                assert false : "Unreachable!";
        }
    }

    /**
     * Check if this is a Global region
     */
    public boolean isGlobal() {
        return kind == TYPE_GLOBAL;
    }

    /**
     * Check if this is a Register region
     */
    public boolean isReg() {
        return kind == TYPE_REG;
    }

    /**
     * Check if this is a Local region
     */
    public boolean isLocal() {
        return kind == TYPE_LOCAL;
    }

    /**
     * Check if this is a Heap region
     */
    public boolean isHeap() {
        return kind == TYPE_HEAP;
    }

    /**
     * Check if this is a Unique region
     */
    public boolean isUnique() {
        return kind == TYPE_UNIQUE;
    }

    /**
     * Setter for the size of this region
     */
    public void setSize(long size) {
        this.size = size;
    }

    /**
     * Getter for the size of this region
     */
    public long getSize() {
        return size;
    }

    /**
     * Getter for the region kind
     */
    public int getKind() {
        return kind;
    }

    /**
     * Getter for the base of this region
     */
    public long getBase() {
        return base;
    }

    // thread-unsafe
    protected static long getBase(long increment) {
        long res = accumulator;
        accumulator += increment;
        int bits = GlobalState.arch.getWordBits();
        long mask = (bits == 64) ? -1L : (1L << bits) - 1;
        accumulator &= mask;
        return res;
    }

    /**
     * @hidden
     */
    public abstract boolean equals(Object obj);

    /**
     * @hidden
     */
    public abstract int hashCode();

    /**
     * @hidden
     */
    @Override
    public String toString() {
        switch (kind) {
            case TYPE_GLOBAL:
                return "GLOBAL";
            case TYPE_LOCAL:
                Local local = (Local) this;
                return local.getFunction().getName() + "@Local";
            case TYPE_HEAP:
                Heap heap = (Heap) this;
                return heap.getAllocAddress().toString() + "@Heap" + ":" + Long.toHexString(heap.getSize()) + "h";
            case TYPE_REG:
                return "REG";
            case TYPE_UNIQUE:
                return "UNIQUE";
            default:
                return null;
        }
    }

}

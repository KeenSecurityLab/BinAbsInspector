package com.bai.env.region;

import com.bai.env.Context;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import org.apache.commons.lang3.tuple.ImmutableTriple;

public class Heap extends RegionBase { // malloc region, allocation site sensitive with malloc context

    public static final int DEFAULT_SIZE = 0x6400000;
    private static final Map<ImmutableTriple<Address, Context, Boolean>, Heap> pool = new HashMap<>();
    private final Address allocAddress;
    private final Context context;
    private boolean valid;
    private Address freeSite = null;

    private Heap(Address allocAddress, Context context, boolean valid) {
        super(TYPE_HEAP, DEFAULT_SIZE); // 100MB default
        this.allocAddress = allocAddress;
        this.context = context;
        this.valid = valid;
    }

    private Heap(Address allocAddress, Context context, long size, boolean valid) {
        super(TYPE_HEAP, size);
        this.allocAddress = allocAddress;
        this.context = context;
        this.valid = valid;
    }

    public Context getContext() {
        return context;
    }

    public Address getAllocAddress() {
        return allocAddress;
    }

    public Address getFreeSite() {
        assert (!valid);
        return freeSite;
    }

    private void setFreeSite(Address addr) {
        assert (addr != null && !valid);
        freeSite = addr;
    }

    public boolean isValid() {
        return valid;
    }

    public Heap toInvalid(Address addr) {
        if (valid == true) {
            Heap invalidHeap = getHeap(allocAddress, context, 0, false);
            invalidHeap.setFreeSite(addr);
            return invalidHeap;
        }
        return this;
    }

    @Override
    public boolean equals(Object other) {
        if (this == other) {
            return true;
        }

        if (other instanceof Heap) {
            Heap heap = (Heap) other;
            if (this.allocAddress.equals(heap.allocAddress) && this.context == heap.context
                    && this.valid == heap.valid) {
                return true;
            }
        }

        return false;
    }

    @Override
    public int hashCode() {
        int res = allocAddress.hashCode() * 31 + context.hashCode();
        res += valid ? 1 : 0;
        return res;
    }

    public static void resetPool() {
        pool.clear();
    }

    public static Heap getHeap(Address allocSite, Context context, boolean valid) {
        ImmutableTriple<Address, Context, Boolean> key = new ImmutableTriple<>(allocSite, context, valid);
        Heap oldHeap = pool.get(key);
        if (oldHeap != null) {
            return oldHeap;
        }
        Heap newHeap = new Heap(allocSite, context, valid);
        pool.put(key, newHeap);
        return newHeap;
    }

    public static Heap getHeap(Address allocSite, Context context, long size, boolean valid) {
        Heap res = getHeap(allocSite, context, valid);
        if (size < DEFAULT_SIZE) {
            res.setSize(size);
        } else {
            res.setSize(DEFAULT_SIZE);
        }
        return res;
    }

}

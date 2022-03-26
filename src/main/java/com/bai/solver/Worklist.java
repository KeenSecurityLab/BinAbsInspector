package com.bai.solver;

import ghidra.program.model.address.Address;
import java.util.Comparator;
import java.util.PriorityQueue;

public class Worklist extends PriorityQueue<Address> {

    static class WtoComparator implements Comparator<Address> {
        private CFG cfg;

        public WtoComparator(CFG cfg) {
            this.cfg = cfg;
        }

        @Override
        public int compare(Address addr0, Address addr1) {
            int order0 = cfg.getWTOMap().get(addr0);
            int order1 = cfg.getWTOMap().get(addr1);
            return Integer.compare(order0, order1);
        }
    }

    public Worklist(CFG cfg) {
        super(cfg.getSum(), new WtoComparator(cfg));
    }

    public void push(Address addr) {
        assert (addr != null);
        if (!super.contains(addr)) {
            super.add(addr);
        }
    }

    public Address pop() {
        return super.poll();
    }
}

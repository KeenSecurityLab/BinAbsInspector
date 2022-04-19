package com.bai.env.region;


import com.bai.env.context;
import ghidra.program.model.address.Address;
import org.junit.Test;
import org.mockito.Mockito;

public class HeapTest {

    @Test
    public void testGetHeap() {
        Address a1 = Mockito.mock(Address.class);
        context c1 = Mockito.mock(context.class);
        Heap h1 = Heap.getHeap(a1, c1, true);
        Heap h2 = Heap.getHeap(a1, c1, true);
        assert h1 == h2;

        Address a2 = Mockito.mock(Address.class);
        context c2 = Mockito.mock(context.class);
        h1 = Heap.getHeap(a2, c2, 0x100, true);
        h2 = Heap.getHeap(a2, c2, 0x200, true);
        assert h1 == h2;
        assert h1.getSize() == 0x200;
    }

    @Test
    public void testToInvalid() {
        Address a1 = Mockito.mock(Address.class);
        context c1 = Mockito.mock(context.class);
        Heap h1 = Heap.getHeap(a1, c1, true);
        Heap h2 = h1.toInvalid(a1);
        Heap h3 = Heap.getHeap(a1, c1, true);
        assert h1.equals(h3);
        assert !h3.equals(h2);
    }
}
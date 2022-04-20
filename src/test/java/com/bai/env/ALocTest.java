package com.bai.env;

import static org.mockito.Mockito.when;

import com.bai.env.region.Global;
import com.bai.env.region.Local;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import com.bai.Utils;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class ALocTest {

    Function mockFunction = Mockito.mock(Function.class);
    Address mockAddress = Mockito.mock(Address.class);

    @Before
    public void setUp() {
        when(mockFunction.getName()).thenReturn("mockFunction");
        when(mockAddress.toString()).thenReturn("0xdeadbeef");
        Utils.mockArchitecture(true);
    }

    @Test
    public void testCompareTo() {
        ALoc a1 = ALoc.getALoc(Global.getInstance(), 0, 4);
        ALoc a2 = ALoc.getALoc(Global.getInstance(), 4, 8);
        assert a1.compareTo(a2) < 0;

        a1 = ALoc.getALoc(Global.getInstance(), 0, 4);
        a2 = ALoc.getALoc(Global.getInstance(), 0,2);
        assert a1.compareTo(a2) == 0;

        a1 = ALoc.getALoc(Local.getLocal(mockFunction), 0, 4);
        a2 = ALoc.getALoc(Local.getLocal(mockFunction), 8, 12);
        assert a1.compareTo(a2) < 0;
    }

}
package com.bai.env;

import static org.mockito.Mockito.when;

import com.bai.Utils;
import com.bai.util.Config;
import com.bai.util.GlobalState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import org.junit.Test;
import org.mockito.Mockito;

public class ContextTransitionTableTest {

    @Test
    public void testTransitionTable() {
        Utils.mockArchitecture(true);
        Utils.mockCfgForContext();
        GlobalState.config = new Config();

        ContextTransitionTable transitionTable = new ContextTransitionTable();
        Function f1 = Mockito.mock(Function.class);
        Context c = Context.getEntryContext(f1);

        Address callSite1 = Mockito.mock(Address.class);
        when(callSite1.getOffset()).thenReturn(0x1010L);
        transitionTable.add(callSite1, c);
        Context c1 = Context.getContext(c, callSite1, f1);
        transitionTable.add(callSite1, c1);

        Function f2 = Mockito.mock(Function.class);
        Address callSite2 = Mockito.mock(Address.class);
        when(callSite2.getOffset()).thenReturn(0x2010L);
        Context c2 = Context.getContext(c1, callSite2, f2);
        transitionTable.add(callSite2, c2);

        long[] target = {0L, 0L, 0x2010L};
        long[] expect = {0L, 0x1010L, 0x2010L};
        assert transitionTable.get(callSite2, target).contains(expect);
    }

}
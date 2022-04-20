package com.bai.env.region;

import com.bai.util.Config;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class LocalTest {

    @Before
    public void setUp() {
        Config config = Mockito.mock(Config.class);
        GlobalState.config = config;
    }

    @Test
    public void testGetLocal() {
       Function func1 = Mockito.mock(Function.class);

       Local local1 = Local.getLocal(func1);
       Local local2 = Local.getLocal(func1);
       assert local1 == local2;

       Local.resetPool();
       Local local3 = Local.getLocal(func1);
       assert local1 != local3;
       assert local1.equals(local3);
       assert local3.getFunction() == func1;
    }
}
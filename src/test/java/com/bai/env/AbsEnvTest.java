package com.bai.env;

import com.bai.env.region.Unique;
import com.bai.util.Config;
import com.bai.util.GlobalState;
import com.bai.Utils;
import org.junit.Before;
import org.junit.Test;

public class AbsEnvTest {

    @Before
    public void setUp() {
        GlobalState.config = new Config();
        Utils.mockArchitecture(true);
    }

    @Test
    public void testExactlySet() {
        //     AAAAAAAA <- old ALoc
        //     BBBBBBBB <- this ALoc

        // fully overwrite, strong update
        AbsEnv absEnv = new AbsEnv();
        KSet bot = new KSet(32);
        ALoc a1 = ALoc.getALoc(Unique.getInstance(), 0, 4);
        KSet k1 = new KSet(32).insert(new AbsVal(0xAAAAAAAAL));
        absEnv.set(a1, k1, true);

        ALoc a2 = ALoc.getALoc(Unique.getInstance(), 0, 4);
        KSet k2 = new KSet(32).insert(new AbsVal(0xBBBBBBBBL));
        absEnv.set(a2, k2, true);

        assert absEnv.getEnvMap().getValueOr(a2, bot).equals(k2);

        // fully overwrite, strong update bot
        absEnv.set(a1, new KSet(32), true);
        assert absEnv.getEnvMap().size() == 0;

        // fully overwrite, weak update
        absEnv.set(a1, k1, true);
        absEnv.set(a2, k2, false);
        KSet expect = new KSet(32)
                .insert(new AbsVal(0xAAAAAAAAL))
                .insert(new AbsVal(0xBBBBBBBBL));
        assert absEnv.getEnvMap().getValueOr(a2, bot).equals(expect);
    }

    @Test
    public void testLeftPartialSet() {
        //  ----AAAAAAAA <- old ALoc
        //  BBBBBBBB---- <- this ALoc

        AbsEnv absEnv = new AbsEnv();
        KSet bot = new KSet(32);
        ALoc a1 = ALoc.getALoc(Unique.getInstance(), 2, 4);
        KSet k1 = new KSet(32).insert(new AbsVal(0xAAAAAAAAL));
        ALoc a2 = ALoc.getALoc(Unique.getInstance(), 0, 4);
        KSet k2 = new KSet(32).insert(new AbsVal(0xBBBBBBBBL));

        // strong update
        absEnv.set(a1, k1, true);
        absEnv.set(a2, k2, true);
        ALoc a0t2 = ALoc.getALoc(Unique.getInstance(), 0, 2);
        KSet expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a0t2, bot).equals(expect);

        ALoc a2t4 = ALoc.getALoc(Unique.getInstance(), 2, 2);
        expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a2t4, bot).equals(expect);

        ALoc a4t6 = ALoc.getALoc(Unique.getInstance(), 4, 2);
        expect = new KSet(16).insert(new AbsVal(0xAAAAL));
        assert absEnv.getEnvMap().getValueOr(a4t6, bot).equals(expect);

        // strong update bot
        absEnv = new AbsEnv();
        absEnv.set(a1, k1, true);
        absEnv.set(a2, bot, true);
        assert absEnv.getEnvMap().findEntry(a0t2).isEmpty();
        assert absEnv.getEnvMap().findEntry(a2t4).isEmpty();

        expect = new KSet(16).insert(new AbsVal(0xAAAA));
        assert absEnv.getEnvMap().getValueOr(a4t6, bot).equals(expect);

        // weak update
        absEnv = new AbsEnv();
        absEnv.set(a1, k1, true);
        absEnv.set(a2, k2, false);
        expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a0t2, bot).equals(expect);

        expect = new KSet(16)
                .insert(new AbsVal(0xBBBBL))
                .insert(new AbsVal(0xAAAAL));
        assert absEnv.getEnvMap().getValueOr(a2t4, bot).equals(expect);

        expect = new KSet(16).insert(new AbsVal(0xAAAAL));
        assert absEnv.getEnvMap().getValueOr(a4t6, bot).equals(expect);
    }

    @Test
    public void testRightPartialSet() {
        //  AAAAAAAA---- <- old ALoc
        //  ----BBBBBBBB <- this ALoc

        AbsEnv absEnv = new AbsEnv();
        KSet bot = new KSet(32);
        ALoc a1 = ALoc.getALoc(Unique.getInstance(), 0, 4);
        KSet k1 = new KSet(32).insert(new AbsVal(0xAAAAAAAAL));
        ALoc a2 = ALoc.getALoc(Unique.getInstance(), 2, 4);
        KSet k2 = new KSet(32).insert(new AbsVal(0xBBBBBBBBL));

        // strong update
        absEnv.set(a1, k1, true);
        absEnv.set(a2, k2, true);
        ALoc a0t2 = ALoc.getALoc(Unique.getInstance(), 0, 2);
        KSet expect = new KSet(16).insert(new AbsVal(0xAAAAL));
        assert absEnv.getEnvMap().getValueOr(a0t2, bot).equals(expect);

        ALoc a2t4 = ALoc.getALoc(Unique.getInstance(), 2, 2);
        expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a2t4, bot).equals(expect);

        ALoc a4t6 = ALoc.getALoc(Unique.getInstance(), 4, 2);
        expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a4t6, bot).equals(expect);

        // weak update
        absEnv = new AbsEnv();
        absEnv.set(a1, k1, true);
        absEnv.set(a2, k2, false);
        expect = new KSet(16).insert(new AbsVal(0xAAAAL));
        assert absEnv.getEnvMap().getValueOr(a0t2, bot).equals(expect);

        expect = new KSet(16)
                .insert(new AbsVal(0xBBBBL))
                .insert(new AbsVal(0xAAAAL));
        assert absEnv.getEnvMap().getValueOr(a2t4, bot).equals(expect);

        expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a4t6, bot).equals(expect);
    }

    @Test
    public void testFullyOverLapSet() {
        //  ----AAAA---- <- old ALoc
        //  BBBBBBBBBBBB <- this ALoc

        AbsEnv absEnv = new AbsEnv();
        KSet bot = new KSet(32);
        ALoc a1 = ALoc.getALoc(Unique.getInstance(), 2, 4);
        KSet k1 = new KSet(32).insert(new AbsVal(0xAAAAAAAAL));
        ALoc a2 = ALoc.getALoc(Unique.getInstance(), 0, 8);
        KSet k2 = new KSet(64).insert(new AbsVal(0xBBBBBBBBBBBBBBBBL));

        // strong update
        absEnv.set(a1, k1, true);
        absEnv.set(a2, k2, true);

        ALoc a0t2 = ALoc.getALoc(Unique.getInstance(), 0, 2);
        KSet expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a0t2, bot).equals(expect);

        ALoc a2t6 = ALoc.getALoc(Unique.getInstance(), 2, 6);
        expect = new KSet(32).insert(new AbsVal(0xBBBBBBBBL));
        assert absEnv.getEnvMap().getValueOr(a2t6, bot).equals(expect);

        ALoc a6t8 = ALoc.getALoc(Unique.getInstance(), 6, 8);
        expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a6t8, bot).equals(expect);

        // weak update
        absEnv = new AbsEnv();
        absEnv.set(a1, k1, true);
        absEnv.set(a2, k2, false);
        expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a0t2, bot).equals(expect);

        expect = new KSet(32)
                .insert(new AbsVal(0xBBBBBBBBL))
                .insert(new AbsVal(0xAAAAAAAAL));
        assert absEnv.getEnvMap().getValueOr(a2t6, bot).equals(expect);

        expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a6t8, bot).equals(expect);
    }

    @Test
    public void testSubsetOverLapSet() {
        //  AAAAAAAAAAAA <- old ALoc
        //  ----BBBB---- <- this ALoc

        AbsEnv absEnv = new AbsEnv();
        KSet bot = new KSet(32);
        ALoc a1 = ALoc.getALoc(Unique.getInstance(), 0, 8);
        KSet k1 = new KSet(64).insert(new AbsVal(0xBBBBBBBBBBBBBBBBL));
        ALoc a2 = ALoc.getALoc(Unique.getInstance(), 2, 4);
        KSet k2 = new KSet(32).insert(new AbsVal(0xAAAAAAAAL));

        // strong update
        absEnv.set(a1, k1, true);
        absEnv.set(a2, k2, true);

        ALoc a0t2 = ALoc.getALoc(Unique.getInstance(), 0, 2);
        KSet expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a0t2, bot).equals(expect);

        ALoc a2t6 = ALoc.getALoc(Unique.getInstance(), 2, 6);
        expect = new KSet(32).insert(new AbsVal(0xAAAAAAAAL));
        assert absEnv.getEnvMap().getValueOr(a2t6, bot).equals(expect);

        ALoc a6t8 = ALoc.getALoc(Unique.getInstance(), 6, 8);
        expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a6t8, bot).equals(expect);

        // weak update
        absEnv = new AbsEnv();
        absEnv.set(a1, k1, true);
        absEnv.set(a2, k2, false);
        expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a0t2, bot).equals(expect);

        expect = new KSet(32)
                .insert(new AbsVal(0xBBBBBBBBL))
                .insert(new AbsVal(0xAAAAAAAAL));
        assert absEnv.getEnvMap().getValueOr(a2t6, bot).equals(expect);

        expect = new KSet(16).insert(new AbsVal(0xBBBBL));
        assert absEnv.getEnvMap().getValueOr(a6t8, bot).equals(expect);
    }

    @Test
    public void testOverlapMultipleSet() {
        // AAAABBCC
        // DDDDDDDD

        final KSet bot = new KSet(32);
        ALoc a0t2 = ALoc.getALoc(Unique.getInstance(), 0, 2);
        KSet k1 = new KSet(16).insert(new AbsVal(0xAAAAL));
        ALoc a2t3 = ALoc.getALoc(Unique.getInstance(), 2, 1);
        KSet k2 = new KSet(8).insert(new AbsVal(0xBBL));
        ALoc a3t4 = ALoc.getALoc(Unique.getInstance(), 3, 1);
        KSet k3 = new KSet(8).insert(new AbsVal(0xCCL));

        AbsEnv absEnv = new AbsEnv();
        absEnv.set(a0t2, k1, true);
        absEnv.set(a2t3, k2, true);
        absEnv.set(a3t4, k3, true);

        ALoc a4 = ALoc.getALoc(Unique.getInstance(), 0, 4);
        KSet k4 = new KSet(32).insert(new AbsVal(0xDDDDDDDDL));

        // strong update
        absEnv.set(a4, k4, true);
        KSet expect = new KSet(16).insert(new AbsVal(0xDDDDL));
        assert absEnv.getEnvMap().getValueOr(a0t2, bot).equals(expect);

        expect = new KSet(8).insert(new AbsVal(0xDDL));
        assert absEnv.getEnvMap().getValueOr(a2t3, bot).equals(expect);

        assert absEnv.getEnvMap().getValueOr(a3t4, bot).equals(expect);

        // weak update
        absEnv = new AbsEnv();
        absEnv.set(a0t2, k1, true);
        absEnv.set(a2t3, k2, true);
        absEnv.set(a3t4, k3, true);

        absEnv.set(a4, k4, false);

        expect = new KSet(16)
                .insert(new AbsVal(0xDDDDL))
                .insert(new AbsVal(0xAAAAL));
        assert absEnv.getEnvMap().getValueOr(a0t2, bot).equals(expect);

        expect = new KSet(8)
                .insert(new AbsVal(0xDDL))
                        .insert(new AbsVal(0xBBL));
        assert absEnv.getEnvMap().getValueOr(a2t3, bot).equals(expect);

        expect = new KSet(8)
                .insert(new AbsVal(0xDDL))
                .insert(new AbsVal(0xCCL));
        assert absEnv.getEnvMap().getValueOr(a3t4, bot).equals(expect);
    }

    @Test
    public void testExactlyGet() {
        // AAAAAAAA
        // ^^^^^^^^
        AbsEnv absEnv = new AbsEnv();

        ALoc a1 = ALoc.getALoc(Unique.getInstance(), 0, 4);
        KSet k1 = new KSet(32).insert(new AbsVal(0xAAAAAAAAL));

        absEnv.set(a1, k1, true);
        KSet expect = new KSet(32).insert(new AbsVal(0xAAAAAAAAL));
        assert absEnv.get(a1).equals(expect);
    }

    @Test
    public void testLeftPartialGet() {
        //  ----AAAAAAAA <- old ALoc
        //  ^^^^^^^^---- <- this ALoc
        AbsEnv absEnv = new AbsEnv();

        ALoc a1 = ALoc.getALoc(Unique.getInstance(), 2, 4);
        KSet k1 = new KSet(32).insert(new AbsVal(0xAAAAAAAAL));

        absEnv.set(a1, k1, true);
        ALoc a2 = ALoc.getALoc(Unique.getInstance(), 0, 4);
        KSet expect = new KSet(32);
        assert absEnv.get(a2).equals(expect);
    }

    @Test
    public void testRightPartialGet() {
        //  AAAAAAAA---- <- old ALoc
        //  ----^^^^^^^^ <- this ALoc
        AbsEnv absEnv = new AbsEnv();

        ALoc a1 = ALoc.getALoc(Unique.getInstance(), 0, 4);
        KSet k1 = new KSet(32).insert(new AbsVal(0xAAAAAAAAL));

        absEnv.set(a1, k1, true);
        ALoc a2 = ALoc.getALoc(Unique.getInstance(), 2, 4);
        KSet expect = new KSet(32);
        assert absEnv.get(a2).equals(expect);
    }

    @Test
    public void testFullyOverlapGet() {
        // ----AAAAAAAA----
        // ^^^^^^^^^^^^^^^^
        AbsEnv absEnv = new AbsEnv();

        ALoc a1 = ALoc.getALoc(Unique.getInstance(), 2, 2);
        KSet k1 = new KSet(16).insert(new AbsVal(0xAAAAAAAAL));

        absEnv.set(a1, k1, true);

        ALoc a2 = ALoc.getALoc(Unique.getInstance(), 0, 8);
        KSet expect = new KSet(64);
        assert absEnv.get(a2).equals(expect);

        // AAAAAAAA--------
        // ^^^^^^^^^^^^^^^^
        a2 = ALoc.getALoc(Unique.getInstance(), 2, 8);
        expect = new KSet(64);
        assert absEnv.get(a2).equals(expect);

        // ----AAAAAAAA
        // ^^^^^^^^^^^^
        a2 = ALoc.getALoc(Unique.getInstance(), 0, 6);
        expect = new KSet(48);
        assert absEnv.get(a2).equals(expect);


    }

    @Test
    public void testSubsetOverlapGet() {
        // AAAAAAAAAAAAAAAA
        // ----^^^^^^^^----
        AbsEnv absEnv = new AbsEnv();

        ALoc a1 = ALoc.getALoc(Unique.getInstance(), 0, 8);
        KSet k1 = new KSet(64).insert(new AbsVal(0xAAAAAAAAAAAAAAAAL));
        absEnv.set(a1, k1, true);

        ALoc a2 = ALoc.getALoc(Unique.getInstance(), 2, 4);
        KSet expect = new KSet(32).insert(new AbsVal(0xAAAAAAAAL));
        assert absEnv.get(a2).equals(expect);
    }

    @Test
    public void testOverlapMultipleGet() {
        // AAAABBCC
        // ^^^^^^^^

        // little endian
        AbsEnv absEnv = new AbsEnv();
        ALoc a0t2 = ALoc.getALoc(Unique.getInstance(), 0, 2);
        KSet k1 = new KSet(16).insert(new AbsVal(0xAAAAL));
        ALoc a2t3 = ALoc.getALoc(Unique.getInstance(), 2, 1);
        KSet k2 = new KSet(8).insert(new AbsVal(0xBBL));
        ALoc a3t4 = ALoc.getALoc(Unique.getInstance(), 3, 1);
        KSet k3 = new KSet(8).insert(new AbsVal(0xCCL));

        absEnv.set(a0t2, k1, true);
        absEnv.set(a2t3, k2, true);
        absEnv.set(a3t4, k3, true);

        ALoc a4 = ALoc.getALoc(Unique.getInstance(), 0, 4);
        KSet expect = new KSet(32).insert(new AbsVal(0xCCBBAAAAL));
        assert absEnv.get(a4).equals(expect);

        Utils.mockArchitecture(false);
        // big endian
        absEnv = new AbsEnv();

        absEnv.set(a0t2, k1, true);
        absEnv.set(a2t3, k2, true);
        absEnv.set(a3t4, k3, true);

        expect = new KSet(32).insert(new AbsVal(0xAAAABBCCL));
        assert absEnv.get(a4).equals(expect);
    }
}
package com.bai.env;

import com.bai.Utils;
import java.math.BigInteger;
import org.junit.Before;
import org.junit.Test;

public class AbsValTest {
    @Before
    public void setUp() {
       Utils.mockArchitecture(true);
    }

    @Test
    public void testBytesToLong() {
        byte[] b = Utils.fromHexString("0000112233445566");
        assert AbsVal.bytesTolong(b) == 0x6655443322110000L;

        Utils.mockArchitecture(false);
        assert AbsVal.bytesTolong(b) == 0x0000112233445566L;
    }

    @Test
    public void testBytesToBigInteger() {
        byte[] b = Utils.fromHexString("1122334455667788AABBCCDD");
        assert AbsVal.bytesToBigInteger(b).equals(new BigInteger("DDCCBBAA8877665544332211", 16));

        Utils.mockArchitecture(false);
        assert AbsVal.bytesToBigInteger(b).equals(new BigInteger("1122334455667788AABBCCDD", 16));
    }

}

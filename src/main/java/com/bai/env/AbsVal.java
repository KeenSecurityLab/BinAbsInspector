package com.bai.env;

import com.bai.env.region.Global;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import java.math.BigInteger;

public class AbsVal {

    protected RegionBase region;

    protected BigInteger bigVal;

    protected long value;

    protected static AbsVal True;

    protected static AbsVal False;

    static {
        True = new AbsVal(Global.getInstance(), 1);
        False = new AbsVal(Global.getInstance(), 0);
    }

    /**
     * Get a pointer AbsVal which points to the beginning of region.
     * @param region Accepts only Global, Local, Heap region
     * @return AbsVal
     */
    public static AbsVal getPtr(RegionBase region) {
        return AbsVal.getPtr(region, region.getBase());
    }

    /**
     * Get a pointer AbsVal which points to the region with offset.
     * @param region Accepts only Global, Local, Heap region
     * @param offset offset to the beginning off region.
     * @return AbsVal
     */
    public static AbsVal getPtr(RegionBase region, long offset) {
        assert region.isGlobal() || region.isHeap() || region.isLocal();
        return new AbsVal(region, offset);
    }

    public AbsVal(long value) {
        this(Global.getInstance(), value);
    }

    public AbsVal(BigInteger bigVal) {
        this(Global.getInstance(), bigVal);
    }

    public AbsVal(RegionBase region, long value) {
        this.region = region;
        this.value = value;
    }

    public AbsVal(RegionBase region, BigInteger bigVal) {
        assert (bigVal.signum() >= 0);
        this.region = region;
        if (isReducible(bigVal)) {
            this.value = reduce(bigVal);
        } else {
            assert (bigVal.bitLength() > 64);
            this.bigVal = bigVal;
        }
    }

    public boolean isBigVal() {
        return bigVal != null;
    }

    public RegionBase getRegion() {
        return region;
    }

    public long getValue() {
        return value;
    }

    public long getOffset() {
        return value - region.getBase();
    }

    public boolean isZero() {
        if (bigVal != null) {
            return bigVal.signum() == 0;
        } else {
            return value == 0;
        }
    }

    public boolean isNegative(int bits) {
        assert region.isGlobal() : "Can only apply on global AbsVal";
        if (bits <= 64) {
            return ((value >>> (bits - 1)) & 1) == 1;
        } else {
            if (bigVal == null) {
                return false;
            } else {
                return bigVal.testBit(bits - 1);
            }
        }
    }

    protected static boolean isReducible(BigInteger bigValue) {
        return bigValue.bitLength() <= Long.SIZE;
    }

    protected static long reduce(BigInteger bigValue) {
        assert (isReducible(bigValue));
        return bigValue.longValue();
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj instanceof AbsVal) {
            AbsVal rhs = (AbsVal) obj;
            if (this.region.equals(rhs.region)) {
                if (this.bigVal != null && rhs.bigVal != null) {
                    return this.bigVal.equals(rhs.bigVal);
                }
                if (this.bigVal == null && rhs.bigVal == null) {
                    return this.value == rhs.value;
                }
            }
        }

        return false;
    }

    public int hashCode() {
        if (this.bigVal != null) {
            return region.hashCode() + bigVal.intValue();
        }
        return region.hashCode() + (int) value;
    }

    public BigInteger toBigInteger(int bits, boolean signed) {
        if (signed) {
            return bigVal != null ? toSigned(bigVal, bits) : toSigned(value, bits);
        } else {
            return bigVal != null ? bigVal : toUnsigned(value);
        }
    }

    public static BigInteger toSigned(BigInteger bigValue, int bits) {
        boolean msb = bigValue.testBit(bits - 1);
        if (msb) {
            BigInteger complement = BigInteger.ONE.shiftLeft(bits);
            return bigValue.subtract(complement);
        }
        return bigValue;
    }

    protected static BigInteger toSigned(long value, int bits) {
        if (bits <= Long.SIZE) {
            long sValue = signExtendToLong(value, bits);
            return BigInteger.valueOf(sValue);
        }

        return toUnsigned(value);
    }

    public static BigInteger toUnsigned(BigInteger bigValue, int bits) {
        if (bigValue.signum() == -1) {
            return BigInteger.ONE.shiftLeft(bits).add(bigValue);
        }
        return bigValue;
    }

    protected static BigInteger toUnsigned(long value) {
        if (value < 0) {
            return BigInteger.ONE.shiftLeft(Long.SIZE).add(BigInteger.valueOf(value));
        }

        return BigInteger.valueOf(value);

    }

    public static long bytesTolong(byte[] bytes) {
        assert bytes.length <= 8;
        int len = bytes.length;

        long res = 0;
        if (GlobalState.arch.isLittleEndian()) {
            for (int i = 0; i < len; i++) {
                res |= (bytes[i] & 0xFFL) << (i * 8);
            }
        } else {
            for (int i = len - 1; i >= 0; i--) {
                res |= (bytes[i] & 0xFFL) << ((len - i - 1) * 8);
            }
        }
        return res;
    }

    public static BigInteger bytesToBigInteger(byte[] bytes) {
        assert bytes.length > 8;
        BigInteger res = null;
        if (GlobalState.arch.isLittleEndian()) {
            byte[] tmp = new byte[bytes.length];
            for (int i = 0; i < bytes.length; i++) {
                tmp[bytes.length - i - 1] = bytes[i];
            }
            res = new BigInteger(1, tmp);
        } else {
            res = new BigInteger(1, bytes);
        }
        return res;
    }

    public static AbsVal bytesToAbsVal(RegionBase region, byte[] bytes) {
        if (bytes.length <= 8) {
            return new AbsVal(region, bytesTolong(bytes));
        } else {
            return new AbsVal(region, bytesToBigInteger(bytes));
        }
    }

    public static long signExtendToLong(long value, int bits) {
        assert (bits <= 64);

        if (bits < 64) {
            long sMask = 1L << (bits - 1);
            long sign = value & sMask;
            if (sign != 0) {
                long ext = -(1L << bits);
                value = ext | value;
            }
        }
        return value;
    }



    @Override
    public String toString() {
        if (bigVal == null) {
            return "<" + region.toString() + ", " + Long.toHexString(value) + "h>";
        } else {
            return "<" + region.toString() + ", " + bigVal.toString(16) + "h>";
        }
    }
}

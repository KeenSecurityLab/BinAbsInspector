package com.bai.env;

import com.bai.env.region.Global;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import java.math.BigInteger;

/** Abstract Value */
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
     * @hidden
     * @deprecated Redundant method, to be removed
     * Get a pointer AbsVal which points to the beginning of region.
     * @param region Accepts only Global, Local, Heap region
     * @return AbsVal
     */
    public static AbsVal getPtr(RegionBase region) {
        return AbsVal.getPtr(region, region.getBase());
    }

    /**
     * @hidden
     * @deprecated Redundant method, to be removed
     * Get a pointer AbsVal which points to the region with offset.
     * @param region Accepts only Global, Local, Heap region
     * @param offset offset to the beginning off region.
     * @return AbsVal
     */
    public static AbsVal getPtr(RegionBase region, long offset) {
        assert region.isGlobal() || region.isHeap() || region.isLocal();
        return new AbsVal(region, offset);
    }

    /**
     * Create an abstract value for a constant inside global region with a long
     */
    public AbsVal(long value) {
        this(Global.getInstance(), value);
    }

    /**
     * Create an abstract value for a constant inside global region with a BigInteger
     */
    public AbsVal(BigInteger bigVal) {
        this(Global.getInstance(), bigVal);
    }

    /**
     * Create an abstract value with a region and a long as inner value
     */
    public AbsVal(RegionBase region, long value) {
        this.region = region;
        this.value = value;
    }

    /**
     * Create an abstract value with a region and a BigInteger as inner value
     */
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

    /**
     * Check if this abstract value is stored as a BigInteger
     */
    public boolean isBigVal() {
        return bigVal != null;
    }

    /**
     * Getter for the region of this abstract value
     */
    public RegionBase getRegion() {
        return region;
    }

    /**
     * Getter for the long value of this abstract value, if it is stored as a long
     */
    public long getValue() {
        return value;
    }

    /**
     * Get the offset starting from the region of this abstract value
     */
    public long getOffset() {
        return value - region.getBase();
    }

    /**
     * @hidden
     * @deprecated Method with ambiguous semantics, to be changed
     */
    public boolean isZero() {
        if (bigVal != null) {
            return bigVal.signum() == 0;
        } else {
            return value == 0;
        }
    }

    protected boolean isNegative(int bits) {
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

    /**
     * @hidden
     */
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

    /**
     * @hidden
     */
    public int hashCode() {
        if (this.bigVal != null) {
            return region.hashCode() + bigVal.intValue();
        }
        return region.hashCode() + (int) value;
    }

    /**
     * Convert this abstract value into a BigInteger
     * @param bits The bit width of this abstract value
     * @param signed the signedness for this abstract value
     * @return Converted BigInteger
     */
    public BigInteger toBigInteger(int bits, boolean signed) {
        if (signed) {
            return bigVal != null ? toSigned(bigVal, bits) : toSigned(value, bits);
        } else {
            return bigVal != null ? bigVal : toUnsigned(value);
        }
    }

    /**
     * @hidden
     */
    public static BigInteger toSigned(BigInteger bigValue, int bits) {
        boolean msb = bigValue.testBit(bits - 1);
        if (msb) {
            BigInteger complement = BigInteger.ONE.shiftLeft(bits);
            return bigValue.subtract(complement);
        }
        return bigValue;
    }

    /**
     * @hidden
     */
    public static BigInteger toSigned(long value, int bits) {
        if (bits <= Long.SIZE) {
            long sValue = signExtendToLong(value, bits);
            return BigInteger.valueOf(sValue);
        }
        return toUnsigned(value);
    }

    /**
     * @hidden
     */
    public static BigInteger toUnsigned(BigInteger bigValue, int bits) {
        if (bigValue.signum() == -1) {
            return BigInteger.ONE.shiftLeft(bits).add(bigValue);
        }
        return bigValue;
    }

    /**
     * @hidden
     */
    public static BigInteger toUnsigned(long value) {
        if (value < 0) {
            return BigInteger.ONE.shiftLeft(Long.SIZE).add(BigInteger.valueOf(value));
        }
        return BigInteger.valueOf(value);
    }

    /**
     * @hidden
     */
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

    /**
     * @hidden
     */
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

    protected static AbsVal bytesToAbsVal(RegionBase region, byte[] bytes) {
        if (bytes.length <= 8) {
            return new AbsVal(region, bytesTolong(bytes));
        } else {
            return new AbsVal(region, bytesToBigInteger(bytes));
        }
    }

    /**
     * @hidden
     */
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

    /**
     * @hidden
     */
    @Override
    public String toString() {
        if (bigVal == null) {
            return "<" + region.toString() + ", " + Long.toHexString(value) + "h>";
        } else {
            return "<" + region.toString() + ", " + bigVal.toString(16) + "h>";
        }
    }

}

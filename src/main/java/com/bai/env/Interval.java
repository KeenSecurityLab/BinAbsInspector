package com.bai.env;

import java.math.BigInteger;
import java.util.Objects;

/** The interval for constraint solving result. */
public class Interval {

    private long lower;
    private long upper;
    private BigInteger lowerBig;
    private BigInteger upperBig;

    public static Interval TRUE = Interval.of(1L, 1L);
    public static Interval FALSE = Interval.of(0L, 0L);
    public static Interval UNKNOWN = Interval.of(0L, 1L);

    /**
     * Interval: lower bound and upper bound are inclusive, [lower,upper].
     * @param lower
     * @param upper
     */
    public Interval(long lower, long upper) {
        this.lower = lower;
        this.upper = upper;
    }

    public Interval(BigInteger lowerBig, BigInteger upperBig) {
        this.lowerBig = lowerBig;
        this.upperBig = upperBig;
    }

    public static Interval of(long lower, long upper) {
        return new Interval(lower, upper);
    }

    public static Interval of(BigInteger lowerBig, BigInteger upperBig) {
        return new Interval(lowerBig, upperBig);
    }

    public long getLower() {
        return lower;
    }

    public long getUpper() {
        return upper;
    }

    public BigInteger getLowerBig() {
        return lowerBig;
    }

    public BigInteger getUpperBig() {
        return upperBig;
    }

    public boolean isBig() {
        return lowerBig != null && upperBig != null;
    }

    @Override
    public String toString() {
        if (TRUE.equals(this)) {
            return "TRUE";
        } else if (FALSE.equals(this)) {
            return "FALSE";
        } else if (UNKNOWN.equals(this)) {
            return "UNKNOWN";
        } else if (isBig()) {
            return "[" + lowerBig.toString(16) + "h, " + upperBig.toString(16) + "h]";
        } else {
            return "[" + Long.toHexString(lower) + "h, " + Long.toHexString(upper) + "h]";
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        Interval interval = (Interval) o;
        return lower == interval.lower && upper == interval.upper && Objects.equals(lowerBig, interval.lowerBig)
                && Objects.equals(upperBig, interval.upperBig);
    }

    @Override
    public int hashCode() {
        return Objects.hash(lower, upper, lowerBig, upperBig);
    }
}

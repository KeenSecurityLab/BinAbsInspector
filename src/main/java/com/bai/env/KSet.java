package com.bai.env;

import com.bai.env.region.Global;
import com.google.errorprone.annotations.CheckReturnValue;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import java.math.BigInteger;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.javimmutable.collections.JImmutableSet;
import org.javimmutable.collections.util.JImmutables;

/** KSet */
public class KSet implements Iterable<AbsVal> {

    private static JImmutableSet<AbsVal> TrueSet = JImmutables.set();
    private static JImmutableSet<AbsVal> FalseSet = JImmutables.set();
    private static JImmutableSet<AbsVal> UnknownSet = JImmutables.set();

    private static final Map<Long, KSet> topMap = new HashMap<>();
    private static final Map<Long, KSet> trueMap = new HashMap<>();
    private static final Map<Long, KSet> falseMap = new HashMap<>();
    private static final Map<Long, KSet> unknownMap = new HashMap<>();

    static {
        TrueSet = TrueSet.insert(AbsVal.True);
        FalseSet = FalseSet.insert(AbsVal.False);
        UnknownSet = UnknownSet.insert(AbsVal.True).insert(AbsVal.False);
    }

    private JImmutableSet<AbsVal> kSet;

    private final int bits;

    protected long taints;

    /**
     * Constructor for an empty KSet
     * @param bits Bit width for this KSet
     */
    public KSet(int bits) {
        this(bits, 0);
    }

    /**
     * Constructor for an empty KSet with taint information
     * @param bits Bit width for this KSet
     * @param taints Taint bitmap for this KSet
     */
    public KSet(int bits, long taints) {
        this.kSet = JImmutables.set();
        this.bits = bits;
        this.taints = taints;
    }


    /**
     * Shallow copy constructor
     * @param obj The other KSet to be copied
     */
    public KSet(KSet obj) {
        this.kSet = obj.kSet;
        this.bits = obj.bits;
        this.taints = obj.taints;
    }

    /**
     * Constructor with a specific set
     * @param kSet The underlying immutable set 
     * @param bits Bit width for this KSet
     */
    public KSet(JImmutableSet<AbsVal> kSet, int bits) {
        this(kSet, bits, 0);
    }

    /**
     * Constructor with a specific set and taint information
     * @param kSet The underlying immutable set 
     * @param bits Bit width for this KSet
     * @param taints Taint bitmap for this KSet
     */
    public KSet(JImmutableSet<AbsVal> kSet, int bits, long taints) {
        this.kSet = kSet;
        this.bits = bits;
        this.taints = taints;
    }

    /**
     * Get the bit width of this KSet object 
     * @return Bit width
     */
    public int getBits() {
        return bits;
    }

    /**
     * Get the underlying immutable set
     * @return Inner immutable set 
     */
    public JImmutableSet<AbsVal> getInnerSet() {
        return kSet;
    }

    /**
     * Get a clean Top KSet object
     * @return Top object without taint information
     */
    public static KSet getTop() {
        return getTop(0);
    }

    /**
     * Get a Top KSet with taint information
     * @param taints Taint bitmap for this Top
     * @return Top object with taint bitmap
     */
    public static KSet getTop(long taints) {
        KSet res = topMap.get(taints);
        if (res == null) {
            res = new KSet(null, 0, taints);
            topMap.put(taints, res);
        }
        return res;
    }

    /**
     * Get a Bottom KSet object
     * @param bits bit width for Bottom object
     * @return Bottom Kset object
     */
    public static KSet getBot(int bits) {
        return new KSet(bits, 0);
    }

    /**
     * Get a True KSet with taint information
     * @param taints Taint bitmap for this Top
     * @return True object with taint bitmap
     */
    public static KSet getTrue(long taints) {
        KSet res = trueMap.get(taints);
        if (res == null) {
            res = new KSet(TrueSet, 8, taints);
            trueMap.put(taints, res);
        }
        return res;
    }

    /**
     * Get a False KSet with taint information
     * @param taints Taint bitmap for this Top
     * @return False object with taint bitmap
     */
    public static KSet getFalse(long taints) {
        KSet res = falseMap.get(taints);
        if (res == null) {
            res = new KSet(FalseSet, 8, taints);
            falseMap.put(taints, res);
        }
        return res;
    }

    /**
     * Get a Unknown KSet with taint information
     * @param taints Taint bitmap for this Top
     * @return Unknown object with taint bitmap
     */
    public static KSet getUnknown(long taints) {
        KSet res = unknownMap.get(taints);
        if (res == null) {
            res = new KSet(UnknownSet, 8, taints);
            unknownMap.put(taints, res);
        }
        return res;
    }


    /**
     * Check whether the corresponding bit in taint bitmap is set or not
     * @param sourceId Indicate which taint number to be checked
     * @return Check result
     */
    public boolean checkTaints(int sourceId) {
        assert (sourceId >= 0 && sourceId < 64);

        if (isBot()) {
            return false;
        }

        return ((taints >>> sourceId) & 1) == 1;
    }

    /**
     * Get taint bitmap
     * @return Taint bitmap as a long
     */
    public long getTaints() {
        return taints;
    }

    /**
     * Test taint information is valid or not
     * @return Test result: true for valid, false otherwise
     */
    public boolean isTaint() {
        return taints != 0;
    }

    /**
     * Set new taint information for an existing KSet
     * @param newTaints new taint bitmap to be set
     * @return A new KSet object with new taint bitmap
     */
    @CheckReturnValue
    public KSet setTaints(long newTaints) {
        if (!this.isNormal()) {
            // when BOT get taint, it becomes TOP
            // retrieve top from topMap
            return getTop(newTaints);
        }
        return new KSet(kSet, bits, newTaints);
    }


    /**
     * Test whether this is a Top object
     * @return Test result
     */
    public boolean isTop() {
        return kSet == null;
    }

    /**
     * Test whether this is a Bottom object
     * @return Test result
     */
    public boolean isBot() {
        return kSet != null && kSet.isEmpty();
    }

    /**
     * Test whether this is a normal KSet (i.e., KSet with a nonempty underlying set)
     * @return Test result
     */
    public boolean isNormal() {
        return kSet != null && !kSet.isEmpty();
    }

    /**
     * Test whether this is a True KSet
     * @return Test result
     */
    public boolean isTrue() {
        if (kSet != null) {
            if (kSet.size() == 1) {
                AbsVal val = kSet.iterator().next();
                return val.equals(AbsVal.True);
            }
        }

        return false;
    }

    /**
     * Test whether this is a False KSet
     * @return Test result
     */
    public boolean isFalse() {
        if (kSet != null) {
            if (kSet.size() == 1) {
                AbsVal val = kSet.iterator().next();
                return val.equals(AbsVal.False);
            }
        }
        return false;
    }

    /**
     * Test whether this is a Unknown KSet
     * @return Test result
     */
    public boolean isUnknown() {
        return !isFalse() && !isTrue();
    }

    /**
     * Test whether this is a KSet with only one element
     * @return Test result
     */
    public boolean isSingleton() {
        return kSet.size() == 1;
    }

    /**
     * Abstract union operation on KSet
     * @param rhs KSet object to be joined with the old one
     * @return If join result is different from the old one, a reference to the new KSet object. Otherwise, null 
     */
    public KSet join(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        if (rhs.isBot()) {
            return null;
        }

        if (isBot()) {
            if (rhs.isTop()) {
                return rhs;
            }
            if (rhs.isNormal()) {
                return new KSet(rhs);
            }
        }

        long newTaints = this.taints | rhs.taints;
        if (isTop()) {
            KSet tmp = getTop(newTaints);
            if (tmp.equals(this)) {
                return null;
            }
            return tmp;
        }
        if (rhs.isTop()) {
            return getTop(newTaints);
        }

        // quick path
        if (kSet.size() + rhs.kSet.size() >= GlobalState.config.getK()) {
            return getTop(newTaints);
        }

        JImmutableSet<AbsVal> res = this.kSet.insertAll(rhs.kSet);
        if (res.equals(this.kSet) && newTaints == this.taints) {
            return null;
        }
        return new KSet(res, bits, newTaints);
    }

    /**
     * Insert an abstract value into this KSet. If beyond limit K, return a Top object
     * @param val Abstract value to be inserted
     * @return Result KSet object, may be Top or Normal KSet object
     */
    @CheckReturnValue
    public KSet insert(AbsVal val) {
        // Disabled for test
        // assert ((bits > 64 && val.bigVal != null) || (bits <= 64 && val.bigVal == null));

        if (isTop()) {
            return this;
        }

        if (kSet.size() >= GlobalState.config.getK()) {
            return getTop(taints);
        }

        return new KSet(kSet.insert(val), bits, taints);
    }

    /**
     * Remove an abstract value from this KSet object
     * @param val Abstract value to be removed
     * @return Result KSet object, may be Top, Normal or Bottom KSet
     */
    @CheckReturnValue
    public KSet remove(AbsVal val) {
        if (isTop()) {
            return this;
        }
        return new KSet(kSet.delete(val), bits, taints);
    }

    protected static long getMask(int bits) {
        return bits == 64 ? -1L : (1L << bits) - 1;
    }

    protected static BigInteger getBigMask(int bits) {
        return BigInteger.ONE.shiftLeft(bits).subtract(BigInteger.ONE);
    }

    protected boolean isShiftExceedBits(AbsVal op) {
        return op.bigVal != null || (op.value >= bits || op.value < 0);
    }

    /**
     * Computes region of addition and multiplication operation.
     * This can only be done for the following situation:
     * G + G => G; G + H => H; G + L => L
     * @param op1 AbsVal
     * @param op2 AbsVal
     * @return Region
     */
    protected static RegionBase getRegionAddMult(AbsVal op1, AbsVal op2) {
        if (op1.region.isGlobal()) {
            return op2.region;
        }
        if (op2.region.isGlobal()) {
            return op1.region;
        }
        return null;
    }


    /**
     * Computes region of subtraction operation.
     * This can only be done for the following situation:
     * G - G => G; L - G => L; H - G = H;
     * H - H => G; L - L => G
     * @param op1 AbsVal
     * @param op2 AbsVal
     * @return Region
     */
    protected static RegionBase getRegionSub(AbsVal op1, AbsVal op2) {
        if (op1.region.equals(op2.region)) {
            return Global.getInstance();
        }
        if (op2.region.isGlobal()) {
            return op1.region;
        }
        return null;
    }

    /**
     * Computes region of division and remainder operation.
     * This can only be done for the following situation:
     * G / G => G; L / G => L; H / G = H
     * @param op1 AbsVal
     * @param op2 AbsVal
     * @return Region
     */
    protected static RegionBase getRegionDivRem(AbsVal op1, AbsVal op2) {
        if (op2.region.isGlobal()) {
            return op1.region;
        }
        return null;
    }

    /**
     * Computes region of left/right shift operation.
     * This can only be done for the following situation:
     * G & G => G; L & G => L; H & G = H;
     * L & L => G; H & H => G
     * @param op1 AbsVal
     * @param op2 AbsVal
     * @return Region
     */
    protected static RegionBase getRegionBinaryLogic(AbsVal op1, AbsVal op2) {
        if (op1.region.equals(op2.region)) {
            return Global.getInstance();
        }
        if (op1.region.isGlobal()) {
            return op2.region;
        }
        if (op2.region.isGlobal()) {
            return op1.region;
        }
        return null;
    }

    protected long getBinaryTaintResult(KSet rhs) {
        return this.taints | rhs.taints;
    }

    /**
     * @hidden
     */
    public KSet add(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op1 : kSet) {
            for (AbsVal op2 : rhs.kSet) {
                RegionBase region = getRegionAddMult(op1, op2);
                if (region != null) {
                    if (res.kSet.size() == GlobalState.config.getK()) {
                        return getTop(taintRes);
                    }
                    if (bits <= 64) {
                        assert (op1.bigVal == null && op2.bigVal == null);
                        res.kSet = res.kSet.insert(new AbsVal(region, (op1.value + op2.value) & getMask(bits)));
                    } else {
                        BigInteger bigOp1 = op1.toBigInteger(bits, false);
                        BigInteger bigOp2 = op2.toBigInteger(bits, false);
                        BigInteger tmp = bigOp1.add(bigOp2).and(getBigMask(bits));
                        res.kSet = res.kSet.insert(new AbsVal(region, tmp));
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet sub(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);

        for (AbsVal op1 : kSet) {
            for (AbsVal op2 : rhs.kSet) {
                RegionBase region = getRegionSub(op1, op2);
                if (region != null) {
                    if (res.kSet.size() == GlobalState.config.getK()) {
                        return getTop(taintRes);
                    }
                    if (bits <= 64) {
                        assert (op1.bigVal == null && op2.bigVal == null);
                        res.kSet = res.kSet.insert(new AbsVal(region, op1.value - op2.value & getMask(bits)));
                    } else {
                        BigInteger bigOp1 = op1.toBigInteger(bits, true);
                        BigInteger bigOp2 = op2.toBigInteger(bits, true);
                        BigInteger tmp = bigOp1.subtract(bigOp2).and(getBigMask(bits));
                        tmp = AbsVal.toUnsigned(tmp, bits);
                        res.kSet = res.kSet.insert(new AbsVal(region, tmp));
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet mult(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op1 : kSet) {
            for (AbsVal op2 : rhs.kSet) {
                RegionBase region = getRegionAddMult(op1, op2);
                if (region != null) {
                    if (res.kSet.size() == GlobalState.config.getK()) {
                        return getTop(taintRes);
                    }
                    if (bits <= 64) {
                        assert (op1.bigVal == null && op2.bigVal == null);
                        res.kSet = res.kSet.insert(new AbsVal(region, (op1.value * op2.value) & getMask(bits)));
                    } else {
                        BigInteger bigOp1 = op1.toBigInteger(bits, false);
                        BigInteger bigOp2 = op2.toBigInteger(bits, false);
                        BigInteger tmp = bigOp1.multiply(bigOp2).and(getBigMask(bits));
                        res.kSet = res.kSet.insert(new AbsVal(region, tmp));
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet div(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op1 : kSet) {
            for (AbsVal op2 : rhs.kSet) {
                if (op2.isZero()) {
                    continue;
                }
                RegionBase region = getRegionDivRem(op1, op2);
                if (region != null) {
                    if (res.kSet.size() == GlobalState.config.getK()) {
                        return getTop(taintRes);
                    }
                    if (bits <= 64) {
                        assert (op1.bigVal == null && op2.bigVal == null);
                        res.kSet = res.kSet
                                .insert(new AbsVal(region, Long.divideUnsigned(op1.value, op2.value) & getMask(bits)));
                    } else {
                        BigInteger bigOp1 = op1.toBigInteger(bits, false);
                        BigInteger bigOp2 = op2.toBigInteger(bits, false);
                        BigInteger tmp = bigOp1.divide(bigOp2).and(getBigMask(bits));
                        res.kSet = res.kSet.insert(new AbsVal(region, tmp));
                    }
                }

            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet sdiv(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op1 : kSet) {
            for (AbsVal op2 : rhs.kSet) {
                if (op2.isZero()) {
                    continue;
                }
                RegionBase region = getRegionDivRem(op1, op2);
                if (region != null) {
                    if (res.kSet.size() == GlobalState.config.getK()) {
                        return getTop(taintRes);
                    }
                    if (bits <= 64) {
                        assert (op1.bigVal == null && op2.bigVal == null);
                        res.kSet = res.kSet.insert(
                                new AbsVal(region,
                                        (AbsVal.signExtendToLong(op1.value, bits)
                                                / AbsVal.signExtendToLong(op2.value, bits)) & getMask(bits)));

                    } else {
                        BigInteger bigOp1 = op1.toBigInteger(bits, true);
                        BigInteger bigOp2 = op2.toBigInteger(bits, true);
                        BigInteger tmp = AbsVal.toUnsigned(bigOp1.divide(bigOp2).and(getBigMask(bits)), bits);
                        res.kSet = res.kSet.insert(new AbsVal(region, tmp));
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet rem(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op1 : kSet) {
            for (AbsVal op2 : rhs.kSet) {
                if (op2.isZero()) {
                    continue;
                }
                RegionBase region = getRegionDivRem(op1, op2);
                if (region != null) {
                    if (res.kSet.size() == GlobalState.config.getK()) {
                        return getTop(taintRes);
                    }
                    if (bits <= 64) {
                        assert (op1.bigVal == null && op2.bigVal == null);
                        res.kSet = res.kSet.insert(
                                new AbsVal(op1.region, Long.remainderUnsigned(op1.value, op2.value) & getMask(bits)));
                    } else {
                        BigInteger bigOp1 = op1.toBigInteger(bits, false);
                        BigInteger bigOp2 = op2.toBigInteger(bits, false);
                        BigInteger tmp = bigOp1.remainder(bigOp2).and(getBigMask(bits));
                        res.kSet = res.kSet.insert(new AbsVal(op1.region, tmp));
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet srem(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op1 : kSet) {
            for (AbsVal op2 : rhs.kSet) {
                if (op2.isZero()) {
                    continue;
                }
                RegionBase region = getRegionDivRem(op1, op2);
                if (region != null) {
                    if (res.kSet.size() == GlobalState.config.getK()) {
                        return getTop(taintRes);
                    }
                    if (bits <= 64) {
                        assert (op1.bigVal == null && op2.bigVal == null);
                        res.kSet = res.kSet.insert(
                                new AbsVal(op1.region,
                                        (AbsVal.signExtendToLong(op1.value, bits)
                                                % AbsVal.signExtendToLong(op2.value, bits))
                                                & getMask(bits)));
                    } else {
                        BigInteger bigOp1 = op1.toBigInteger(bits, true);
                        BigInteger bigOp2 = op2.toBigInteger(bits, true);
                        BigInteger tmp = AbsVal.toUnsigned(bigOp1.remainder(bigOp2).and(getBigMask(bits)), bits);
                        res.kSet = res.kSet.insert(new AbsVal(op1.region, tmp));
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet lshift(KSet rhs) {
        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op2 : rhs.kSet) {
            if (op2.region.isGlobal()) {
                if (isShiftExceedBits(op2)) {
                    for (AbsVal op1 : kSet) {
                        if (res.kSet.size() == GlobalState.config.getK()) {
                            return getTop(taintRes);
                        }
                        res.kSet = res.kSet.insert(new AbsVal(op1.region, 0));
                    }
                } else {
                    for (AbsVal op1 : kSet) {
                        if (res.kSet.size() == GlobalState.config.getK()) {
                            return getTop(taintRes);
                        }
                        if (bits <= 64) {
                            assert (op1.bigVal == null);
                            res.kSet = res.kSet.insert(
                                    new AbsVal(op1.region, (op1.value << op2.value) & getMask(bits)));
                        } else {
                            BigInteger bigOp1 = op1.toBigInteger(bits, false);
                            BigInteger tmp = bigOp1.shiftLeft((int) op2.value).and(getBigMask(bits));
                            res.kSet = res.kSet.insert(new AbsVal(op1.region, tmp));
                        }
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet rshift(KSet rhs) {
        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op2 : rhs.kSet) {
            if (op2.region.isGlobal()) {
                if (isShiftExceedBits(op2)) {
                    for (AbsVal op1 : kSet) {
                        if (res.kSet.size() == GlobalState.config.getK()) {
                            return getTop(taintRes);
                        }
                        res.kSet = res.kSet.insert(new AbsVal(op1.region, 0));
                    }
                } else {
                    for (AbsVal op1 : kSet) {
                        if (res.kSet.size() == GlobalState.config.getK()) {
                            return getTop(taintRes);
                        }
                        if (bits <= 64) {
                            assert (op1.bigVal == null);
                            res.kSet = res.kSet.insert(
                                    new AbsVal(op1.region, (op1.value >>> op2.value) & getMask(bits)));
                        } else {
                            BigInteger bigOp1 = op1.toBigInteger(bits, false);
                            BigInteger tmp = bigOp1.shiftRight((int) op2.value).and(getBigMask(bits));
                            res.kSet = res.kSet.insert(new AbsVal(op1.region, tmp));
                        }
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet srshift(KSet rhs) {
        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op2 : rhs.kSet) {
            if (op2.region.isGlobal()) {
                if (isShiftExceedBits(op2)) {
                    for (AbsVal op1 : kSet) {
                        if (res.kSet.size() == GlobalState.config.getK()) {
                            return getTop(taintRes);
                        }
                        AbsVal tmp;
                        if (op1.isNegative(bits)) {
                            if (bits <= 64) {
                                tmp = new AbsVal(op1.region, getMask(bits));
                            } else {
                                tmp = new AbsVal(op1.region, getBigMask(bits));
                            }
                        } else {
                            tmp = new AbsVal(op1.region, 0);
                        }
                        res.kSet = res.kSet.insert(tmp);
                    }
                } else {
                    for (AbsVal op1 : kSet) {
                        if (res.kSet.size() == GlobalState.config.getK()) {
                            return getTop(taintRes);
                        }
                        if (bits <= 64) {
                            assert (op1.bigVal == null);
                            res.kSet = res.kSet.insert(
                                    new AbsVal(op1.region, (op1.value >> op2.value) & getMask(bits)));
                        } else {
                            BigInteger bigOp1 = op1.toBigInteger(bits, true);
                            BigInteger tmp = AbsVal.toUnsigned(bigOp1.shiftRight((int) op2.value).and(getBigMask(bits)),
                                    bits);
                            res.kSet = res.kSet.insert(new AbsVal(op1.region, tmp));
                        }
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet int_xor(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op1 : kSet) {
            for (AbsVal op2 : rhs.kSet) {
                RegionBase region = getRegionBinaryLogic(op1, op2);
                if (region != null) {
                    if (res.kSet.size() == GlobalState.config.getK()) {
                        return getTop(taintRes);
                    }
                    if (bits <= 64) {
                        assert (op1.bigVal == null && op2.bigVal == null);
                        res.kSet = res.kSet.insert(new AbsVal(region, (op1.value ^ op2.value) & getMask(bits)));
                    } else {
                        BigInteger bigOp1 = op1.toBigInteger(bits, false);
                        BigInteger bigOp2 = op2.toBigInteger(bits, false);
                        BigInteger tmp = bigOp1.xor(bigOp2).and(getBigMask(bits));
                        res.kSet = res.kSet.insert(new AbsVal(region, tmp));
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet int_and(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op1 : kSet) {
            for (AbsVal op2 : rhs.kSet) {
                RegionBase region = getRegionBinaryLogic(op1, op2);
                if (region != null) {
                    if (res.kSet.size() == GlobalState.config.getK()) {
                        return getTop(taintRes);
                    }
                    if (bits <= 64) {
                        assert (op1.bigVal == null && op2.bigVal == null);
                        res.kSet = res.kSet.insert(new AbsVal(region, (op1.value & op2.value) & getMask(bits)));
                    } else {
                        BigInteger bigOp1 = op1.toBigInteger(bits, false);
                        BigInteger bigOp2 = op2.toBigInteger(bits, false);
                        BigInteger tmp = bigOp1.and(bigOp2).and(getBigMask(bits));
                        res.kSet = res.kSet.insert(new AbsVal(region, tmp));
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet int_or(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op1 : kSet) {
            for (AbsVal op2 : rhs.kSet) {
                RegionBase region = getRegionBinaryLogic(op1, op2);
                if (region != null) {
                    if (res.kSet.size() == GlobalState.config.getK()) {
                        return getTop(taintRes);
                    }
                    if (bits <= 64) {
                        assert (op1.bigVal == null && op2.bigVal == null);
                        res.kSet = res.kSet.insert(new AbsVal(region, (op1.value | op2.value) & getMask(bits)));
                    } else {
                        BigInteger bigOp1 = op1.toBigInteger(bits, false);
                        BigInteger bigOp2 = op2.toBigInteger(bits, false);
                        BigInteger tmp = bigOp1.or(bigOp2).and(getBigMask(bits));
                        res.kSet = res.kSet.insert(new AbsVal(region, tmp));
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet int_2comp() {
        if (isTop()) {
            return this;
        }

        KSet res = new KSet(bits, taints);
        for (AbsVal op : kSet) {
            if (bits <= 64) {
                res.kSet = res.kSet.insert(new AbsVal(op.region, (-op.value) & getMask(bits)));
            } else {
                BigInteger bigOp = op.toBigInteger(bits, true);
                BigInteger tmp = bigOp.negate().and(getBigMask(bits));
                tmp = AbsVal.toUnsigned(tmp, bits);
                res.kSet = res.kSet.insert(new AbsVal(op.region, tmp));
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet int_negate() {
        if (isTop()) {
            return this;
        }

        KSet res = new KSet(bits, taints);
        for (AbsVal op : kSet) {
            if (bits <= 64) {
                res.kSet = res.kSet.insert(new AbsVal(op.region, (~op.value) & getMask(bits)));
            } else {
                BigInteger tmp = op.toBigInteger(bits, false);
                for (int i = 0; i < bits; i++) {
                    tmp = tmp.flipBit(i);
                }
                res.kSet = res.kSet.insert(new AbsVal(op.region, tmp));
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet int_zext(int newBits) {
        assert (newBits > bits);

        if (isTop()) {
            return this;
        }
        return new KSet(this.kSet, newBits, this.taints);
    }

    /**
     * @hidden
     */
    public KSet int_sext(int newBits) {
        assert (newBits > bits);

        if (isTop()) {
            return this;
        }

        KSet res = new KSet(newBits, this.taints);
        for (AbsVal op : kSet) {
            BigInteger bigOp = op.toBigInteger(bits, true);
            BigInteger tmp = AbsVal.toUnsigned(bigOp, newBits);
            res.kSet = res.kSet.insert(new AbsVal(op.region, tmp));
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet int_carry(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getUnknown(taintRes);
        }

        boolean hasTrue = false;
        boolean hasFalse = false;
        for (AbsVal op1 : kSet) {
            if (op1.region.isGlobal()) {
                for (AbsVal op2 : rhs.kSet) {
                    if (op2.region.isGlobal()) {
                        if (bits <= 64) {
                            if (Long.compareUnsigned((op1.value + op2.value) & getMask(bits), op1.value) >= 0) {
                                hasFalse = true;
                            } else {
                                hasTrue = true;
                            }
                        } else {
                            BigInteger bigOp1 = op1.toBigInteger(bits, false);
                            BigInteger bigOp2 = op2.toBigInteger(bits, false);
                            if (bigOp1.add(bigOp2).and(getBigMask(bits)).compareTo(bigOp1) >= 0) {
                                hasFalse = true;
                            } else {
                                hasTrue = true;
                            }
                        }
                        if (hasTrue && hasFalse) {
                            return getUnknown(taintRes);
                        }
                    }
                }
            }

        }
        if (hasTrue && !hasFalse) {
            return getTrue(taintRes);
        } else if (hasFalse && !hasTrue) {
            return getFalse(taintRes);
        }
        return getUnknown(taintRes);
    }

    /**
     * @hidden
     */
    public KSet int_scarry(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getUnknown(taintRes);
        }
        boolean sBit1;
        boolean sBit2;
        boolean sBitR;

        boolean hasTrue = false;
        boolean hasFalse = false;

        for (AbsVal op1 : kSet) {
            if (op1.region.isGlobal()) {
                for (AbsVal op2 : rhs.kSet) {
                    if (op2.region.isGlobal()) {
                        if (bits <= 64) {
                            AbsVal r = new AbsVal(op1.value + op2.value);
                            sBit1 = op1.isNegative(bits);
                            sBit2 = op2.isNegative(bits);
                            sBitR = r.isNegative(bits);
                        } else {
                            BigInteger bigOp1 = op1.toBigInteger(bits, false);
                            BigInteger bigOp2 = op2.toBigInteger(bits, false);
                            BigInteger bigRes = bigOp1.add(bigOp2).and(getBigMask(bits));
                            sBit1 = bigOp1.testBit(bits - 1);
                            sBit2 = bigOp2.testBit(bits - 1);
                            sBitR = bigRes.testBit(bits - 1);
                        }
                        if (sBit1 != sBit2) {
                            hasFalse = true;
                        } else {
                            if (sBitR != sBit1) {
                                hasTrue = true;
                            } else {
                                hasFalse = true;
                            }
                        }
                        if (hasTrue && hasFalse) {
                            return getUnknown(taintRes);
                        }
                    }
                }
            }
        }

        if (hasTrue && !hasFalse) {
            return getTrue(taintRes);
        } else if (hasFalse && !hasTrue) {
            return getFalse(taintRes);
        }
        return getUnknown(taintRes);
    }

    /**
     * @hidden
     */
    public KSet int_sborrow(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getUnknown(taintRes);
        }

        boolean hasTrue = false;
        boolean hasFalse = false;
        for (AbsVal op1 : kSet) {
            if (op1.region.isGlobal()) {
                for (AbsVal op2 : rhs.kSet) {
                    if (op2.region.isGlobal()) {
                        BigInteger bigOp1 = op1.toBigInteger(bits, true);
                        BigInteger bigOp2 = op2.toBigInteger(bits, true);
                        BigInteger bigRes = bigOp1.subtract(bigOp2);
                        if (bigRes.signum() > 0 && bigRes.bitLength() > (bits - 1)
                                || bigRes.signum() < 0 && bigRes.bitLength() >= (bits - 1)
                        ) {
                            hasTrue = true;
                        } else {
                            hasFalse = true;
                        }
                        if (hasTrue && hasFalse) {
                            return getUnknown(taintRes);
                        }
                    }
                }
            }
        }
        if (hasTrue && !hasFalse) {
            return getTrue(taintRes);
        } else if (hasFalse && !hasTrue) {
            return getFalse(taintRes);
        }
        return getUnknown(taintRes);
    }

    /**
     * @hidden
     */
    public KSet int_less(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getUnknown(taintRes);
        }
        boolean hasTrue = false;
        boolean hasFalse = false;

        for (AbsVal op1 : kSet) {
            if (op1.region.isGlobal()) {
                for (AbsVal op2 : rhs.kSet) {
                    if (op2.region.isGlobal()) {
                        if (bits <= 64) {
                            if (Long.compareUnsigned(op1.value, op2.value) < 0) {
                                hasTrue = true;
                            } else {
                                hasFalse = true;
                            }
                        } else {
                            BigInteger bigOp1 = op1.toBigInteger(bits, false);
                            BigInteger bigOp2 = op2.toBigInteger(bits, false);
                            if (bigOp1.compareTo(bigOp2) < 0) {
                                hasTrue = true;
                            } else {
                                hasFalse = true;
                            }
                        }
                        if (hasTrue && hasFalse) {
                            return getUnknown(taintRes);
                        }
                    }
                }
            }
        }

        if (hasTrue && !hasFalse) {
            return getTrue(taintRes);
        } else if (hasFalse && !hasTrue) {
            return getFalse(taintRes);
        }

        return getUnknown(taintRes);
    }

    /**
     * @hidden
     */
    public KSet int_sless(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getUnknown(taintRes);
        }
        boolean hasTrue = false;
        boolean hasFalse = false;

        for (AbsVal op1 : kSet) {
            if (op1.region.isGlobal()) {
                for (AbsVal op2 : rhs.kSet) {
                    if (op2.region.isGlobal()) {
                        if (bits <= 64) {
                            boolean sBit1 = op1.isNegative(bits);
                            boolean sBit2 = op2.isNegative(bits);
                            if (sBit1 != sBit2 && sBit1) {
                                hasTrue = true;
                            } else {
                                if (op1.value < op2.value) {
                                    hasTrue = true;
                                } else {
                                    hasFalse = true;
                                }
                            }
                        } else {
                            BigInteger bigOp1 = op1.toBigInteger(bits, true);
                            BigInteger bigOp2 = op2.toBigInteger(bits, true);
                            if (bigOp1.compareTo(bigOp2) < 0) {
                                hasTrue = true;
                            } else {
                                hasFalse = true;
                            }
                        }
                        if (hasTrue && hasFalse) {
                            return getUnknown(taintRes);
                        }
                    }
                }
            }
        }

        if (hasTrue && !hasFalse) {
            return getTrue(taintRes);
        } else if (hasFalse && !hasTrue) {
            return getFalse(taintRes);
        }
        return getUnknown(taintRes);
    }

    /**
     * @hidden
     */
    public KSet int_equal(KSet rhs) {
        if (!isTop() && !rhs.isTop()) {
            assert this.bits == rhs.bits;
        }

        long taintRes = getBinaryTaintResult(rhs);
        if (isTop() || rhs.isTop()) {
            return getUnknown(taintRes);
        }

        if (kSet.size() == 1 && rhs.kSet.size() == 1) {
            if (kSet.equals(rhs.kSet)) {
                return getTrue(taintRes);
            }
            return getFalse(taintRes);
        }

        return getUnknown(taintRes);
    }

    /**
     * @hidden
     */
    public KSet bool_xor(KSet rhs) {
        assert (bits == 8 && rhs.bits == 8);

        long taintRes = getBinaryTaintResult(rhs);
        if (isTrue() && rhs.isTrue()) {
            return getFalse(taintRes);
        }

        if (isTrue() && rhs.isFalse()) {
            return getTrue(taintRes);
        }

        if (isFalse() && rhs.isTrue()) {
            return getTrue(taintRes);
        }

        if (isFalse() && rhs.isFalse()) {
            return getFalse(taintRes);
        }

        return getUnknown(taintRes);
    }

    /**
     * @hidden
     */
    public KSet bool_or(KSet rhs) {
        assert (bits == 8 && rhs.bits == 8);

        long taintRes = getBinaryTaintResult(rhs);
        if (isTrue() || rhs.isTrue()) {
            return getTrue(taintRes);
        }

        if (isFalse() && rhs.isFalse()) {
            return getFalse(taintRes);
        }

        return getUnknown(taintRes);
    }

    /**
     * @hidden
     */
    public KSet bool_and(KSet rhs) {

        long taintRes = getBinaryTaintResult(rhs);
        if (isFalse() || rhs.isFalse()) {
            return getFalse(taintRes);
        }

        if (isTrue() && rhs.isTrue()) {
            return getTrue(taintRes);
        }

        return getUnknown(taintRes);
    }

    /**
     * @hidden
     */
    public KSet bool_not() {

        if (isTrue()) {
            return getFalse(taints);
        } else if (isFalse()) {
            return getTrue(taints);
        } else {
            return getUnknown(taints);
        }
    }

    /**
     * @hidden
     * Concatenation operation that understands the endianess of the data.
     * this KSet contains the most significant part, rhs is least significant part
     *
     * @param rhs least significant part
     * @return KSet
     */
    public KSet piece(KSet rhs) {
        int resBits = bits + rhs.bits;
        long taintRes = getBinaryTaintResult(rhs);

        if (isTop() || rhs.isTop()) {
            return getTop(taintRes);
        }
        KSet res = new KSet(resBits, taintRes);
        if (isBot() || rhs.isBot()) {
            return res;
        }
        for (AbsVal mostPart : kSet) {
            if (mostPart.region.isGlobal()) {
                for (AbsVal leastPart : rhs.kSet) {
                    if (leastPart.region.isGlobal()) {
                        if (resBits <= 64) {
                            long tmp = (mostPart.value << rhs.bits) | leastPart.value;
                            res.kSet = res.kSet.insert(new AbsVal(Global.getInstance(), tmp));
                        } else {
                            BigInteger bigMostPart = mostPart.toBigInteger(bits, false);
                            BigInteger bigLeastPart = leastPart.toBigInteger(rhs.bits, false);
                            BigInteger bigTmp = bigMostPart.shiftLeft(rhs.bits).or(bigLeastPart);
                            res.kSet = res.kSet.insert(new AbsVal(Global.getInstance(), bigTmp));
                        }
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     * Truncate operator that understands the endianess of the data.
     * rhs KSet indicates the number of least significant bytes of this KSets to be thrown away.
     * output is filled with any remaining bytes up to the size of output.
     * If the size of resBits is smaller than the size of this minus rhs,
     * then additional most significant bytes of result will also be truncated.
     *
     * @param rhs
     * @param resBits
     * @return KSet
     */
    public KSet subPiece(KSet rhs, int resBits) {
        assert !rhs.isTop();
        long taintRes = getBinaryTaintResult(rhs);
        if (isTop()) {
            return getTop(taintRes);
        }
        KSet res = new KSet(resBits, taintRes);
        if (isBot()) {
            return res;
        }
        for (AbsVal op : kSet) {
            if (op.region.isGlobal()) {
                for (AbsVal byteCount : rhs.kSet) {
                    if (op.region.isGlobal() && !byteCount.isBigVal()) {
                        if (bits <= 64) {
                            long tmp = (op.value >>> (byteCount.value * 8)) & getMask(resBits);
                            res.kSet = res.kSet.insert(new AbsVal(Global.getInstance(), tmp));
                        } else {
                            BigInteger bigTmp = op.toBigInteger(bits, false);
                            bigTmp = bigTmp.shiftRight((int) byteCount.value * 8).and(getBigMask(resBits));
                            res.kSet = res.kSet.insert(new AbsVal(Global.getInstance(), bigTmp));
                        }
                    }
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet truncate(int begin, long bytes) {
        return this.truncate(begin, (int) bytes);
    }

    /**
     * @hidden
     */
    public KSet truncate(long begin, long bytes) {
        return this.truncate((int) begin, (int) bytes);
    }

    /**
     * @hidden
     */
    public KSet truncate(int begin, int bytes) {

        if (isTop()) {
            return this;
        }
        assert (begin * 8 + bytes * 8 <= this.bits);

        KSet res = new KSet(bytes * 8, taints);
        if (isBot()) {
            return res;
        }
        BigInteger mask;
        if (GlobalState.arch.isLittleEndian()) {
            mask = getBigMask((begin + bytes) * 8);
            for (AbsVal val : this.kSet) {
                BigInteger bigOp = val.toBigInteger(bits, false);
                res.kSet = res.kSet.insert(new AbsVal(val.region, bigOp.and(mask).shiftRight(begin * 8)));
            }
        } else {
            mask = getBigMask(bits - begin * 8);
            for (AbsVal val : this.kSet) {
                BigInteger bigOp = val.toBigInteger(bits, false);
                res.kSet = res.kSet
                        .insert(new AbsVal(val.region, bigOp.and(mask).shiftRight(bits - (begin + bytes) * 8)));
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet concat(KSet following) {

        if (isTop() || following.isTop()) {
            return getTop(taints);
        }

        KSet res = new KSet(this.bits + following.bits);

        if (isBot() || following.isBot()) {
            return res;
        }

        KSet higher = GlobalState.arch.isLittleEndian() ? following : this;
        KSet lower = GlobalState.arch.isLittleEndian() ? this : following;

        for (AbsVal higherOp : higher.kSet) {
            for (AbsVal lowerOp : lower.kSet) {
                if (lowerOp.region.equals(higherOp.region)) {
                    if (res.kSet.size() == GlobalState.config.getK()) {
                        return getTop(taints);
                    }
                    BigInteger bigHigherOp = higherOp.toBigInteger(higher.bits, false);
                    BigInteger bigLowerOp = lowerOp.toBigInteger(lower.bits, false);
                    bigHigherOp = bigHigherOp.shiftLeft(lower.bits);
                    res.kSet = res.kSet.insert(new AbsVal(lowerOp.region, bigHigherOp.add(bigLowerOp)));
                }
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public KSet count_bits(int bits) {
        long taintRes = getBinaryTaintResult(this);
        if (isTop()) {
            return getTop(taintRes);
        }

        KSet res = new KSet(bits, taintRes);
        for (AbsVal op : kSet) {
            if (res.kSet.size() == GlobalState.config.getK()) {
                return getTop(taintRes);
            }
            if (!op.isBigVal()) {
                int bitsCount = Long.bitCount(op.value);
                res.kSet = res.kSet.insert(new AbsVal(op.region, bitsCount & getMask(bits)));
            } else {
                BigInteger bigOp = op.toBigInteger(bits, false);
                int bitsCount = bigOp.bitCount();
                res.kSet = res.kSet.insert(new AbsVal(op.region, bitsCount & getMask(bits)));
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    @Override
    public String toString() {
        if (isTop()) {
            return "TOP#" + taints;
        }
        if (kSet.isEmpty()) {
            return "BOT#" + taints;
        }
        return kSet.toString() + "#" + taints;
    }

    /**
     * @hidden
     */
    @Override
    public boolean equals(Object rhs) {
        if (!(rhs instanceof KSet)) {
            return false;
        }
        KSet other = (KSet) rhs;
        if (this.isNormal() && other.isNormal()) {
            return this.bits == other.bits && this.taints == other.taints && kSet.equals(other.kSet);
        }
        if ((this.isBot() && other.isBot()) || ((this.isTop() && other.isTop()) && (this.taints == other.taints))) {
            return true;
        }
        return false;
    }

    /**
     * @hidden
     */
    @Override
    public int hashCode() {
        if (kSet == null) {
            return (int) ((this.bits * 31) + this.taints);
        } else {
            return (int) (kSet.hashCode() + (this.bits * 31) + this.taints);
        }
    }

    /**
     * @hidden
     */
    @Override
    public Iterator<AbsVal> iterator() {
        return kSet.iterator();
    }
}
package com.bai.env;

import static org.mockito.Mockito.when;

import com.bai.env.region.Global;
import com.bai.env.region.Heap;
import com.bai.env.region.Local;
import com.bai.util.Config;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import com.bai.Utils;
import java.math.BigInteger;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;

public class KSetTest {

    Function mockFunction = Mockito.mock(Function.class);
    Address mockAddress = Mockito.mock(Address.class);
    Context mockContext = Mockito.mock(Context.class);

    @BeforeClass
    public static void initClass() {
        GlobalState.config = new Config();
        Logging.init();
    }

    @Before
    public void setUp() {
        when(mockFunction.getName()).thenReturn("mockFunction");
        when(mockAddress.toString()).thenReturn("0xdeadbeef");
    }

    @Test
    public void testAdd() {
        KSet k1 = new KSet(32)
                .insert(new AbsVal(1));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(2));
        KSet expect = new KSet(32)
                .insert(new AbsVal(3));
        assert k1.add(k2).equals(expect);

        Local local = Local.getLocal(mockFunction);
        k2 = k2.insert(new AbsVal(local, 0x100L));
        expect = expect.insert(new AbsVal(local, 0x101L));
        assert k1.add(k2).equals(expect);

        Heap heap = Heap.getHeap(mockAddress, mockContext, true);
        k1 = k1.insert(new AbsVal(heap, 0x200));
        expect = expect.insert(new AbsVal(heap, 0x202L));
        assert k1.add(k2).equals(expect);

        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.valueOf(1)));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.valueOf(2)));
        expect = new KSet(128)
                .insert(new AbsVal(3));
        assert k1.add(k2).equals(expect);

        // taint
        k1 = new KSet(64).insert(new AbsVal(0)).setTaints(TaintMap.getTaints(0));
        k2 = new KSet(64).insert(new AbsVal(1)).setTaints(TaintMap.getTaints(63));
        KSet res = k1.add(k2);
        assert res.checkTaints(0);
        assert res.checkTaints(63);
    }

    @Test
    public void testSub() {
        KSet k1 = new KSet(32)
                .insert(new AbsVal(2));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(1));
        KSet expect = new KSet(32)
                .insert(new AbsVal(1));
        assert k1.sub(k2).equals(expect);

        Local local = Local.getLocal(mockFunction);
        Heap heap = Heap.getHeap(mockAddress, mockContext, true);

        k1 = new KSet(32)
                .insert(new AbsVal(1))
                .insert(new AbsVal(heap, 0x101L))
                .insert(new AbsVal(local, 0x201L));
        expect = new KSet(32)
                .insert(new AbsVal(0))
                .insert(new AbsVal(heap, 0x100L))
                .insert(new AbsVal(local, 0x200));
        assert k1.sub(k2).equals(expect);

        k2 = new KSet(32)
                .insert(new AbsVal(heap, 0x100L));
        expect = new KSet(32)
                .insert(new AbsVal(0x1));
        assert k1.sub(k2).equals(expect);
    }

    @Test
    public void testMult() {
        KSet k1 = new KSet(32)
                .insert(new AbsVal(2));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(3));
        KSet expect = new KSet(32)
                .insert(new AbsVal(6));
        assert k1.mult(k2).equals(expect);
    }

    @Test
    public void testDiv() {
        KSet k1 = new KSet(32)
                .insert(new AbsVal(Global.getInstance(), 100));

        KSet k2 = new KSet(32)
                .insert(new AbsVal(Global.getInstance(), 0xFFFFFFFEL));

        KSet expect = new KSet(32)
                .insert(new AbsVal(Global.getInstance(), 0));
        assert k1.div(k2).equals(expect);

        k1 = new KSet(32).insert(new AbsVal(Global.getInstance(), 2));
        expect = new KSet(32)
                .insert(new AbsVal(Global.getInstance(), 0x7FFFFFFFL));
        assert k2.div(k1).equals(expect);

        k1 = new KSet(64)
                .insert(new AbsVal(100));
        k2 = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFFFFFFFFEL));
        expect = new KSet(64)
                .insert(new AbsVal(0));
        assert k1.div(k2).equals(expect);

        k1 = new KSet(64)
                .insert(new AbsVal(-2));
        k2 = new KSet(64)
                .insert(new AbsVal(2));
        expect = new KSet(64)
                .insert(new AbsVal(0x7FFFFFFFFFFFFFFFL));
        assert k1.div(k2).equals(expect);

        k1 = new KSet(64)
                .insert(new AbsVal(1))
                .insert(new AbsVal(2));
        k2 = new KSet(64)
                .insert(new AbsVal(0));
        assert k1.div(k2).isBot();
    }

    @Test
    public void testSdiv() {
        // smaller bitWidth, one negative
        KSet k1 = new KSet(32)
                .insert(new AbsVal(100));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(0xFFFFFFFEL));
        KSet expect = new KSet(32)
                .insert(new AbsVal((1L << 32) - 50L));
        assert k1.sdiv(k2).equals(expect);

        k1 = new KSet(32)
                .insert(new AbsVal(0xFFFFFFFEL));
        k2 = new KSet(32)
                .insert(new AbsVal(2));
        expect = new KSet(32)
                .insert(new AbsVal(0xFFFFFFFFL));
        assert k1.sdiv(k2).equals(expect);

        k1 = new KSet(8)
                .insert(new AbsVal(0xFE));
        k2 = new KSet(8)
                .insert(new AbsVal(2));
        expect = new KSet(8)
                .insert(new AbsVal(0xFF));
        assert k1.sdiv(k2).equals(expect);

        // long bitWidth, one negative
        k1 = new KSet(64)
                .insert(new AbsVal(100));
        k2 = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFFFFFFFFEL));
        expect = new KSet(64)
                .insert(new AbsVal(-50));
        assert k1.sdiv(k2).equals(expect);

        k1 = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFFFFFFFFEL));
        k2 = new KSet(64)
                .insert(new AbsVal(2));
        expect = new KSet(64)
                .insert(new AbsVal(-1L));
        assert k1.sdiv(k2).equals(expect);

        // big bitWidth, one negative
        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.valueOf(100)));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.TWO)));
        expect = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.valueOf(50))));
        assert k1.sdiv(k2).equals(expect);

        k1 = new KSet(128)
                .insert(new AbsVal(2));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.TWO)));
        expect = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
        assert k1.sdiv(k2).equals(expect);
    }

    @Test
    public void testRem() {
        // smaller bitWidth
        KSet k1 = new KSet(32)
                .insert(new AbsVal(100));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(3));
        KSet expect = new KSet(32)
                .insert(new AbsVal(1));
        assert k1.rem(k2).equals(expect);

        k1 = new KSet(32)
                .insert(new AbsVal(100));
        k2 = new KSet(32)
                .insert(new AbsVal(0xFFFFFFFD)); // -3
        expect = new KSet(32)
                .insert(new AbsVal(100));
        assert k1.rem(k2).equals(expect);

        // long bitWidth
        k1 = new KSet(32)
                .insert(new AbsVal(100));
        k2 = new KSet(32)
                .insert(new AbsVal(3));
        expect = new KSet(32)
                .insert(new AbsVal(1));
        assert k1.rem(k2).equals(expect);

        k1 = new KSet(32)
                .insert(new AbsVal(100));
        k2 = new KSet(32)
                .insert(new AbsVal(-3));
        expect = new KSet(32)
                .insert(new AbsVal(100));
        assert k1.rem(k2).equals(expect);

        // big bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.valueOf(100)));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.valueOf(3)));
        expect = new KSet(128)
                .insert(new AbsVal(1));
        assert k1.rem(k2).equals(expect);

        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.valueOf(100)));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.valueOf(3))));
        expect = new KSet(128)
                .insert(new AbsVal(100));
        assert k1.rem(k2).equals(expect);
    }

    @Test
    public void testSrem() {
        // smaller bitWidth
        KSet k1 = new KSet(32)
                .insert(new AbsVal(100));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(3));
        KSet expect = new KSet(32)
                .insert(new AbsVal(1));
        assert k1.srem(k2).equals(expect);

        k1 = new KSet(32)
                .insert(new AbsVal(100));
        k2 = new KSet(32)
                .insert(new AbsVal(0xFFFFFFFD)); // -3
        expect = new KSet(32)
                .insert(new AbsVal(1));
        assert k1.srem(k2).equals(expect);

        // long bitWidth
        k1 = new KSet(32)
                .insert(new AbsVal(100));
        k2 = new KSet(32)
                .insert(new AbsVal(3));
        expect = new KSet(32)
                .insert(new AbsVal(1));
        assert k1.srem(k2).equals(expect);

        k1 = new KSet(32)
                .insert(new AbsVal(100));
        k2 = new KSet(32)
                .insert(new AbsVal(-3));
        expect = new KSet(32)
                .insert(new AbsVal(1));
        assert k1.srem(k2).equals(expect);

        // big bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128)));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.valueOf(3)));
        expect = new KSet(128)
                .insert(new AbsVal(1));
        assert k1.srem(k2).equals(expect);

        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128))); // -1
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.valueOf(3)))); // -3
        expect = new KSet(128)
                .insert(new AbsVal(1));
        assert k1.srem(k2).equals(expect);
    }

    @Test
    public void testLShift() {
        KSet k1 = new KSet(16)
                .insert(new AbsVal(1));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(8));
        KSet expect = new KSet(16)
                .insert(new AbsVal(0x100));
        assert k1.lshift(k2).equals(expect);

        k2 = new KSet(64)
                .insert(new AbsVal(16));
        expect = new KSet(16)
                .insert(new AbsVal(0));
        assert k1.lshift(k2).equals(expect);

        // long bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(1));
        k2 = new KSet(64)
                .insert(new AbsVal(64));
        expect = new KSet(64)
                .insert(new AbsVal(0));
        assert k1.lshift(k2).equals(expect);

        // large bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(1));
        k2 = new KSet(16)
                .insert(new AbsVal(128));
        expect = new KSet(128)
                .insert(new AbsVal(0));
        assert k1.lshift(k2).equals(expect);

        k1 = new KSet(128)
                .insert(new AbsVal(1));
        k2 = new KSet(8)
                .insert(new AbsVal(2));
        expect = new KSet(128)
                .insert(new AbsVal(4));
        assert k1.lshift(k2).equals(expect);

        k1 = KSet.getTop(TaintMap.getTaints(2));
        k2 = new KSet(32).insert(new AbsVal(2));
        KSet res = k1.lshift(k2);
        assert res.checkTaints(2);
        assert res.isTop();
    }

    @Test
    public void testRShift() {
        // smaller bitWidth
        KSet k1 = new KSet(16)
                .insert(new AbsVal(0x100));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(8));
        KSet expect = new KSet(16)
                .insert(new AbsVal(1));
        assert k1.rshift(k2).equals(expect);

        k1 = new KSet(32)
                .insert(new AbsVal(1L << 32));
        k2 = new KSet(8)
                .insert(new AbsVal(32));
        expect = new KSet(32)
                .insert(new AbsVal(0));
        assert k1.rshift(k2).equals(expect);

        // long bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(-1L));
        k2 = new KSet(64)
                .insert(new AbsVal(32));
        expect = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFL));
        assert k1.rshift(k2).equals(expect);

        // large bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(127)));
        k2 = new KSet(8)
                .insert(new AbsVal(127));
        expect = new KSet(128)
                .insert(new AbsVal(1));
        assert k1.rshift(k2).equals(expect);

        k1 = new KSet(128)
                .insert(new AbsVal(8));
        k2 = new KSet(8)
                .insert(new AbsVal(2));
        expect = new KSet(128)
                .insert(new AbsVal(2));
        assert k1.rshift(k2).equals(expect);
    }

    @Test
    public void testSRShift() {
        // smaller bitWidth, shift bit >= bitWidth
        // old sign bit is 0
        KSet k1 = new KSet(16)
                .insert(new AbsVal(0x7FFFL));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(16));
        KSet expect = new KSet(16)
                .insert(new AbsVal(0));
        assert k1.srshift(k2).equals(expect);

        k1 = new KSet(64)
                .insert(new AbsVal(0x100));
        k2 = new KSet(64)
                .insert(new AbsVal(64));
        expect = new KSet(64)
                .insert(new AbsVal(0));
        assert k1.srshift(k2).equals(expect);

        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(127).subtract(BigInteger.ONE)));
        k2 = new KSet(64)
                .insert(new AbsVal(130));
        expect = new KSet(128)
                .insert(new AbsVal(0));
        assert k1.srshift(k2).equals(expect);

        // old sign bit is 1
        k1 = new KSet(16)
                .insert(new AbsVal(0x8000));
        k2 = new KSet(32)
                .insert(new AbsVal(16));
        expect = new KSet(16)
                .insert(new AbsVal(0xFFFF));
        assert k1.srshift(k2).equals(expect);

        k1 = new KSet(64)
                .insert(new AbsVal(Long.MIN_VALUE));
        k2 = new KSet(64)
                .insert(new AbsVal(64));
        expect = new KSet(64)
                .insert(new AbsVal(-1L));
        assert k1.srshift(k2).equals(expect);

        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
        k2 = new KSet(64)
                .insert(new AbsVal(130));
        expect = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
        assert k1.srshift(k2).equals(expect);

        // long bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(Long.MAX_VALUE));
        k2 = new KSet(64)
                .insert(new AbsVal(32));
        expect = new KSet(64)
                .insert(new AbsVal(Integer.MAX_VALUE));
        assert k1.srshift(k2).equals(expect);

        k1 = new KSet(64)
                .insert(new AbsVal(-1));
        k2 = new KSet(64)
                .insert(new AbsVal(32));
        expect = new KSet(64)
                .insert(new AbsVal(-1));
        assert k1.srshift(k2).equals(expect);

        // large bitWidth
        // old sign bit is 0
        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(127).subtract(BigInteger.ONE)));
        k2 = new KSet(64)
                .insert(new AbsVal(128 - 16));
        expect = new KSet(128)
                .insert(new AbsVal(0x7FFF));
        assert k1.srshift(k2).equals(expect);

        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(127)));
        k2 = new KSet(64)
                .insert(new AbsVal(128 - 16));
        expect = new KSet(128)
                .insert(new AbsVal(new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFF8000", 16)));
        assert k1.srshift(k2).equals(expect);
    }

    @Test
    public void testXor() {
        // smaller bitWidth
        KSet k1 = new KSet(8)
                .insert(new AbsVal(0xaa));
        KSet k2 = new KSet(8)
                .insert(new AbsVal(0xaa));
        KSet expect = new KSet(8)
                .insert(new AbsVal(0));
        assert k1.int_xor(k2).equals(expect);

        // long bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(0x5555555555555555L));
        k2 = new KSet(64)
                .insert(new AbsVal(0xAAAAAAAAAAAAAAAAL));
        expect = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFFFFFFFFFL));
        assert k1.int_xor(k2).equals(expect);

        // large bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.TEN));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.TEN));
        expect = new KSet(128)
                .insert(new AbsVal(0));
        assert k1.int_xor(k2).equals(expect);
    }

    @Test
    public void testAnd() {
        // smaller bitWidth
        KSet k1 = new KSet(16)
                .insert(new AbsVal(0xAAAA));
        KSet k2 = new KSet(16)
                .insert(new AbsVal(0xFF));
        KSet expect = new KSet(16)
                .insert(new AbsVal(0xAA));
        assert k1.int_and(k2).equals(expect);

        // long bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(0x5555555555555555L));
        k2 = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFL));
        expect = new KSet(64)
                .insert(new AbsVal(0x55555555L));
        assert k1.int_and(k2).equals(expect);

        // large bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(new BigInteger("00555555555555555555555555555555", 16)));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)));
        expect = new KSet(128)
                .insert(new AbsVal(0x5555555555555555L));
        assert k1.int_and(k2).equals(expect);
    }

    @Test
    public void testOr() {
        // smaller bitWidth
        KSet k1 = new KSet(16)
                .insert(new AbsVal(0xAAAA));
        KSet k2 = new KSet(16)
                .insert(new AbsVal(0xFF));
        KSet expect = new KSet(16)
                .insert(new AbsVal(0xAAFF));
        assert k1.int_or(k2).equals(expect);

        // long bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(0x5555555555555555L));
        k2 = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFL));
        expect = new KSet(64)
                .insert(new AbsVal(0x55555555FFFFFFFFL));
        assert k1.int_or(k2).equals(expect);

        // large bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(new BigInteger("00555555555555555555555555555555", 16)));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(64).subtract(BigInteger.ONE)));
        expect = new KSet(128)
                .insert(new AbsVal(new BigInteger("55555555555555FFFFFFFFFFFFFFFF", 16)));
        assert k1.int_or(k2).equals(expect);
    }

    @Test
    public void testSext() {
        // smaller bitWidth to long
        KSet k1 = new KSet(32)
                .insert(new AbsVal(0xFFFFFFFFL));
        KSet expect = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFFFFFFFFFL));
        assert k1.int_sext(64).equals(expect);

        // smaller bitWidth to large bitWidth
        k1 = new KSet(8)
                .insert(new AbsVal(0xff));
        expect = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
        assert k1.int_sext(128).equals(expect);

        // long to large bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(-1L));
        expect = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
        assert k1.int_sext(128).equals(expect);

        // large bitWidth to larger bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
        expect = new KSet(256)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(256).subtract(BigInteger.ONE)));
        assert k1.int_sext(256).equals(expect);

        k1 = new KSet(64)
                .insert(new AbsVal(Long.MIN_VALUE));
        expect = new KSet(128)
                .insert(new AbsVal(new BigInteger("FFFFFFFFFFFFFFFF8000000000000000", 16)));
        assert k1.int_sext(128).equals(expect);

        k1 = new KSet(128)
                .insert(new AbsVal(100));
        expect = new KSet(256)
                .insert(new AbsVal(100));
        assert k1.int_sext(256).equals(expect);

    }

    @Test
    public void testCarry() {
        KSet k1 = new KSet(32)
                .insert(new AbsVal(0xFFFFFFFFL));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(2));
        assert k1.int_carry(k2).isTrue();

        k1 = new KSet(64)
                .insert(new AbsVal(1));
        k2 = new KSet(64)
                .insert(new AbsVal(1));
        assert k1.int_carry(k2).isFalse();

        k1 = new KSet(8)
                .insert(new AbsVal(0x80));
        k2 = new KSet(8)
                .insert(new AbsVal(0x81));
        assert k1.int_carry(k2).isTrue();

        k1 = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFFFFFFFFFL));
        k2 = new KSet(64)
                .insert(new AbsVal(1));
        assert k1.int_carry(k2).isTrue();

        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE));
        assert k1.int_carry(k2).isTrue();
    }

    @Test
    public void testSCarry() {
        // smaller bitWidth
        KSet k1 = new KSet(8)
                .insert(new AbsVal(0x7f));
        KSet k2 = new KSet(8)
                .insert(new AbsVal(1));
        assert k1.int_scarry(k2).isTrue();

        // long bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(Long.MAX_VALUE));
        k2 = new KSet(64)
                .insert(new AbsVal(2));
        assert k1.int_scarry(k2).isTrue();

        k1 = new KSet(64)
                .insert(new AbsVal(Long.MIN_VALUE));
        k2 = new KSet(64)
                .insert(new AbsVal(-1L));
        assert k1.int_scarry(k2).isTrue();

        k1 = new KSet(64)
                .insert(new AbsVal(-1L));
        k2 = new KSet(64)
                .insert(new AbsVal(2));
        assert k1.int_scarry(k2).isFalse();

        // large bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(127).subtract(BigInteger.ONE)));
        k2 = new KSet(128)
                .insert(new AbsVal(1));
        assert k1.int_scarry(k2).isTrue();

        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(127)));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
        assert k1.int_scarry(k2).isTrue();

        k1 = new KSet(128)
                .insert(new AbsVal(1));
        k2 = new KSet(128)
                .insert(new AbsVal(2));
        assert k1.int_scarry(k2).isFalse();
    }

    @Test
    public void testSBorrow() {
        KSet k1 = new KSet(8)
                .insert(new AbsVal(0x80));
        KSet k2 = new KSet(8)
                .insert(new AbsVal(1));
        assert k1.int_sborrow(k2).isTrue();

        k1 = new KSet(8)
                .insert(new AbsVal(0x7f));
        k2 = new KSet(8)
                .insert(new AbsVal(0x80));
        assert k1.int_sborrow(k2).isTrue();

        k1 = new KSet(64)
                .insert(new AbsVal(Long.MIN_VALUE));
        k2 = new KSet(64)
                .insert(new AbsVal(2));
        assert k1.int_sborrow(k2).isTrue();

        k1 = new KSet(64)
                .insert(new AbsVal(-1L));
        k2 = new KSet(64)
                .insert(new AbsVal(2));
        assert k1.int_sborrow(k2).isFalse();

        k1 = new KSet(64)
                .insert(new AbsVal(Long.MAX_VALUE));
        k2 = new KSet(64)
                .insert(new AbsVal(Long.MIN_VALUE));
        assert k1.int_sborrow(k2).isTrue();

        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(127)));
        k2 = new KSet(128)
                .insert(new AbsVal(1));
        assert k1.int_sborrow(k2).isTrue();

        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(127).subtract(BigInteger.ONE)));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(127)));
        assert k1.int_sborrow(k2).isTrue();
    }

    @Test
    public void testLess() {
        // smaller bitWidth
        KSet k1 = new KSet(32)
                .insert(new AbsVal(0));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(0xFFFFFFFFFL));
        assert k1.int_less(k2).isTrue();

        k1 = new KSet(8)
                .insert(new AbsVal(1));
        k2 = new KSet(8)
                .insert(new AbsVal(0xFF));
        assert k1.int_less(k2).isTrue();

        // long bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(0));
        k2 = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFFFFFFFFFL)); // -1
        assert k1.int_less(k2).isTrue();

        k1 = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFFFFFFFFEL));
        k2 = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFFFFFFFFFL));
        assert k1.int_less(k2).isTrue();

        // large bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(0));
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
        assert k1.int_less(k2).isTrue();
    }

    @Test
    public void testSLess() {
        // smaller bitWidth
        KSet k1 = new KSet(32)
                .insert(new AbsVal(0xFFFFFFFFL));
        KSet k2 = new KSet(32)
                .insert(new AbsVal(0));
        assert k1.int_sless(k2).isTrue();

        k1 = new KSet(16)
                .insert(new AbsVal(0));
        k2 = new KSet(16)
                .insert(new AbsVal(100));
        assert k1.int_sless(k2).isTrue();

        k1 = new KSet(8)
                .insert(new AbsVal(0xFF));
        k2 = new KSet(8)
                .insert(new AbsVal(0xFE));
        assert k1.int_sless(k2).isFalse();

        // long bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(0xFFFFFFFFFFFFFFFFL)); // -1
        k2 = new KSet(64)
                .insert(new AbsVal(0));
        assert k1.int_sless(k2).isTrue();

        // large bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE))); // -1
        k2 = new KSet(128)
                .insert(new AbsVal(0));
        assert k1.int_sless(k2).isTrue();

        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.TWO))); // -2
        k2 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE))); // -1
        assert k1.int_sless(k2).isTrue();
    }

    @Test
    public void test2Comp() {
        // smaller bitWidth
        KSet k1 = new KSet(8)
                .insert(new AbsVal(0xff));
        KSet expect = new KSet(8)
                .insert(new AbsVal(1));
        assert k1.int_2comp().equals(expect);

        k1 = new KSet(8)
                .insert(new AbsVal(2));
        expect = new KSet(8)
                .insert(new AbsVal(0xfe));
        assert k1.int_2comp().equals(expect);

        // long bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(-1));
        expect = new KSet(64)
                .insert(new AbsVal(1));
        assert k1.int_2comp().equals(expect);

        k1 = new KSet(64)
                .insert(new AbsVal(2));
        expect = new KSet(64)
                .insert(new AbsVal(-2));
        assert k1.int_2comp().equals(expect);

        // large bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE));
        expect = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
        assert k1.int_2comp().equals(expect);
    }

    @Test
    public void testNegate() {
        // samller bitWidth
        KSet k1 = new KSet(8)
                .insert(new AbsVal(0xff));
        KSet expect = new KSet(8)
                .insert(new AbsVal(0));
        assert k1.int_negate().equals(expect);

        k1 = new KSet(8)
                .insert(new AbsVal(0x55));
        expect = new KSet(8)
                .insert(new AbsVal(0xAA));
        assert k1.int_negate().equals(expect);

        // long bitWidth
        k1 = new KSet(64)
                .insert(new AbsVal(-1));
        expect = new KSet(64)
                .insert(new AbsVal(0));
        assert k1.int_negate().equals(expect);

        k1 = new KSet(64)
                .insert(new AbsVal(0x5555555555555555L));
        expect = new KSet(64)
                .insert(new AbsVal(0xAAAAAAAAAAAAAAAAL));
        assert k1.int_negate().equals(expect);

        // large bitWidth
        k1 = new KSet(128)
                .insert(new AbsVal(0));
        expect = new KSet(128)
                .insert(new AbsVal(BigInteger.ONE.shiftLeft(128).subtract(BigInteger.ONE)));
        assert k1.int_negate().equals(expect);

        k1 = new KSet(128)
                .insert(new AbsVal(new BigInteger("00555555555555555555555555555555", 16)));
        expect = new KSet(128)
                .insert(new AbsVal(new BigInteger("FFAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 16)));
        assert k1.int_negate().equals(expect);
    }

    @Test
    public void testTruncate() {
        Utils.mockArchitecture(true);
        KSet k1 = new KSet(32)
                .insert(new AbsVal(0x11223344));

        KSet expect = new KSet(16).insert(new AbsVal(0x3344));
        assert k1.truncate(0, 2).equals(expect);

        expect = new KSet(0).insert(new AbsVal(0));
        assert k1.truncate(0, 0).equals(expect);

        assert k1.truncate(0, 4).equals(k1);

        k1 = new KSet(128).insert(new AbsVal(new BigInteger("1122334455667788AABBCCDDEEFF0000", 16)));

        expect = new KSet(64).insert(new AbsVal(0xAABBCCDDEEFF0000L));
        assert k1.truncate(0, 8).equals(expect);

        Utils.mockArchitecture(false);
        expect = new KSet(64).insert(new AbsVal(0x1122334455667788L));
        assert k1.truncate(0, 8).equals(expect);
    }

    @Test
    public void testConcat() {
        Utils.mockArchitecture(true);
        KSet k1 = new KSet(32).insert(new AbsVal(0x11223344L));
        KSet k2 = new KSet(32).insert(new AbsVal(0x55667788L));

        KSet expect = new KSet(64).insert(new AbsVal(0x5566778811223344L));
        assert k1.concat(k2).equals(expect);

        k1 = new KSet(8).insert(new AbsVal(0xAA));
        k2 = new KSet(8).insert(new AbsVal(0xBB));
        expect = new KSet(16).insert(new AbsVal(0xBBAA));
        assert k1.concat(k2).equals(expect);

        Utils.mockArchitecture(false);

        k1 = new KSet(32).insert(new AbsVal(0x11223344L));
        k2 = new KSet(32).insert(new AbsVal(0x55667788L));

        expect = new KSet(64).insert(new AbsVal(0x1122334455667788L));
        assert k1.concat(k2).equals(expect);

        k1 = new KSet(8).insert(new AbsVal(0xAA));
        k2 = new KSet(8).insert(new AbsVal(0xBB));
        expect = new KSet(16).insert(new AbsVal(0xAABB));
        assert k1.concat(k2).equals(expect);
    }

    @Test
    public void testPiece() {
        // with Top
        KSet k1 = new KSet(null, 32);
        KSet k2 = new KSet(32).insert(new AbsVal(0x11223344));

        KSet expect = new KSet(null, 64);
        assert k1.piece(k2).equals(expect);

        // with bot
        k1 = new KSet(32);
        k2 = new KSet(16);
        expect = new KSet(48);
        assert k1.piece(k2).equals(expect);

        // smaller bitwidth
        k1 = new KSet(16).insert(new AbsVal(0x1122));
        k2 = new KSet(16).insert(new AbsVal(0x3344));
        expect = new KSet(32).insert(new AbsVal(0x11223344));
        assert k1.piece(k2).equals(expect);

        // long bitwidth
        k1 = new KSet(32).insert(new AbsVal(0xFFEEDDCCL));
        k2 = new KSet(32).insert(new AbsVal(0x44332211L));
        expect = new KSet(64).insert(new AbsVal(0xFFEEDDCC44332211L));
        assert k1.piece(k2).equals(expect);

        // large bitwidth
        k1 = new KSet(64).insert(new AbsVal(0x1122));
        k2 = new KSet(64).insert(new AbsVal(0x3344));
        expect = new KSet(128).insert(new AbsVal(new BigInteger("11220000000000003344", 16)));
        assert k1.piece(k2).equals(expect);
    }

    @Test
    public void testSubPiece() {
        // with Top
        KSet k1 = new KSet(null, 32);
        KSet k2 = new KSet(32).insert(new AbsVal(16));

        KSet expect = new KSet(null, 16);
        assert k1.subPiece(k2, 16).equals(expect);

        // with bot
        k1 = new KSet(32);
        k2 = new KSet(32).insert(new AbsVal(16));

        expect = new KSet(16);
        assert  k1.subPiece(k2, 16).equals(expect);

        // smaller bitWidth
        k1 = new KSet(32).insert(new AbsVal(0x11223344L));
        k2 = new KSet(16).insert(new AbsVal(2));
        expect = new KSet(16).insert(new AbsVal(0x1122));
        assert k1.subPiece(k2, 16).equals(expect);

        k2 = new KSet(32).insert(new AbsVal(0));
        expect = new KSet(8).insert(new AbsVal(0x44));
        assert k1.subPiece(k2, 8).equals(expect);

        // large bitWith
        k1 = new KSet(128).insert(new AbsVal(new BigInteger("1122334455667788AABBCCDDEEFF0000", 16)));
        k2 = new KSet(32).insert(new AbsVal(2));
        expect = new KSet(112).insert(new AbsVal(new BigInteger("1122334455667788AABBCCDDEEFF", 16)));
        assert k1.subPiece(k2, 112).equals(expect);

        expect = new KSet(32).insert(new AbsVal(0xEEFF0000L));
        k2 = new KSet(32).insert(new AbsVal(0));
        assert k1.subPiece(k2, 32).equals(expect);

        k1 = new KSet(128).insert(new AbsVal(new BigInteger("FFFFFFFFFFFFFFFF1122334455667788", 16)));
        k2 = new KSet(32).insert(new AbsVal(8));
        expect = new KSet(64).insert(new AbsVal(0xFFFFFFFFFFFFFFFFL));
        assert k1.subPiece(k2, 64).equals(expect);

        k2 = new KSet(32).insert(new AbsVal(0));
        expect = new KSet(64).insert(new AbsVal(0x1122334455667788L));
        assert k1.subPiece(k2, 64).equals(expect);

    }

}
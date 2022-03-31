package com.bai.solver;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Global;
import com.bai.env.region.Heap;
import com.bai.env.region.Reg;
import com.bai.util.ARMProgramTestBase;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BitVecSort;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.Optimize;
import com.microsoft.z3.Optimize.Handle;
import com.microsoft.z3.Params;
import com.microsoft.z3.Status;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import java.math.BigInteger;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

@SuppressWarnings("unchecked")
public class ConstraintSolverTest extends ARMProgramTestBase {

    private com.microsoft.z3.Context z3Context;
    private Optimize optimize;
    private boolean hasInit = false;

    public void initZ3() {
        if (!hasInit) {
            Map<String, String> config = Map.of("model", "true");
            z3Context = new com.microsoft.z3.Context(config);
            optimize = z3Context.mkOptimize();
            Params params = z3Context.mkParams();
            params.add("timeout", 1000);
            optimize.setParameters(params);
            hasInit = true;
        }
    }

    @Test
    public void testZ3() {
        initZ3();
        Expr r3 = z3Context.mkIntConst("r3");
        Expr r2 = z3Context.mkIntConst("r2");
        BoolExpr boolExpr = z3Context.mkEq(r2, z3Context.mkAdd(r3, r3));
        optimize.Add(boolExpr);

        Expr con = z3Context.mkBoolConst("con");
        boolExpr = z3Context.mkIff(z3Context.mkLe(r3, z3Context.mkInt(11)),
                z3Context.mkEq(con, z3Context.mkTrue()));
        optimize.Add(boolExpr);
        BoolExpr[] constrains = optimize.getAssertions();
        for (BoolExpr constrain : constrains) {
            Logging.warn(constrain.toString());
        }

        Optimize maxOptimize = z3Context.mkOptimize();
        maxOptimize.Add(constrains);
        Optimize minOptimize = z3Context.mkOptimize();
        minOptimize.Add(constrains);
        Optimize.Handle maxHandle = maxOptimize.MkMaximize(r3);
        Optimize.Handle minHandle = minOptimize.MkMinimize(r3);
        Logging.warn("" + maxOptimize.Check(z3Context.mkEq(con, z3Context.mkTrue())).toString());
        Logging.warn("" + maxHandle.getLower() + " " + maxHandle.getUpper());
        Logging.warn("" + minOptimize.Check(z3Context.mkEq(con, z3Context.mkTrue())).toString());
        Logging.warn("" + minHandle.getLower() + " " + minHandle.getUpper());

        maxOptimize = z3Context.mkOptimize();
        maxOptimize.Add(constrains);
        minOptimize = z3Context.mkOptimize();
        minOptimize.Add(constrains);
        maxHandle = maxOptimize.MkMaximize(r2);
        minHandle = minOptimize.MkMinimize(r2);
        Logging.warn("" + maxOptimize.Check(z3Context.mkEq(con, z3Context.mkTrue())).toString());
        Logging.warn("" + maxHandle.getLower() + " " + maxHandle.getUpper());
        Logging.warn("" + minOptimize.Check(z3Context.mkEq(con, z3Context.mkTrue())).toString());
        Logging.warn("" + minHandle.getLower() + " " + minHandle.getUpper());

        Expr test = z3Context.mkIff(
                z3Context.mkEq(
                        z3Context.mkBV(0, 8), z3Context.mkBV(0, 8)),
                z3Context.mkEq(z3Context.mkBoolConst("a"), z3Context.mkTrue())
        );
        Logging.warn(test.toString());
        Logging.warn(test.simplify().toString());

        Expr test1 = z3Context.mkEq(z3Context.mkBoolConst("a"), z3Context.mkTrue());
        Logging.warn(test1.toString());
        Logging.warn(test1.simplify().toString());
    }

    @Test
    public void testVisitCOPY() {
        // (register, 0x8, 4) COPY (const, 0x2000, 4)
        Address instructionAddress = Utils.getDefaultAddress(0x1000);

        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);
        Varnode[] in = {new Varnode(Utils.getConstantAddress(0x2000), GlobalState.arch.getDefaultPointerSize())};
        Varnode out = new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.COPY, in, out);
        ConstraintSolver constraintSolver = new ConstraintSolver();

        AbsEnv tmpEnv = new AbsEnv();
        constraintSolver.visit_COPY(pcode, tmpEnv);
        BoolExpr constrain = constraintSolver.getConstraints()[0];
        Assert.assertEquals(constrain.toString(), "(= bv_0 #x00002000)");

        tmpEnv = new AbsEnv();
        // (register, 0x0, 4) COPY (register, 0x8, 4)
        constraintSolver = new ConstraintSolver();
        in[0] = new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize());
        out = new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize());
        pcode = new PcodeOp(seq, PcodeOp.COPY, in, out);
        constraintSolver.visit_COPY(pcode, tmpEnv);

        // (register, 0x8, 4) COPY (register, 0x0, 4)
        in[0] = new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize());
        out = new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize());
        pcode = new PcodeOp(seq, PcodeOp.COPY, in, out);
        constraintSolver.visit_COPY(pcode, tmpEnv);

        constrain = constraintSolver.getConstraints()[0];
        Assert.assertEquals(constrain.toString(), "(= bv_1 bv_0)");
        constrain = constraintSolver.getConstraints()[1];
        Assert.assertEquals(constrain.toString(), "(= bv_2 bv_1)");
    }

    @Test
    public void testVisitAdd() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_ADD, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_ADD(pcode, tmpEnv);

        BoolExpr constrain = constraintSolver.getConstraints()[0];
        Assert.assertEquals(constrain.toString(), "(= bv_2 (bvadd bv_0 bv_1))");

        in[0] = out;
        in[1] = new Varnode(Utils.getConstantAddress(123), GlobalState.arch.getDefaultPointerSize());
        out = new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize());
        pcode = new PcodeOp(seq, PcodeOp.INT_ADD, in, out);
        constraintSolver.visit_INT_ADD(pcode, tmpEnv);
        constrain = constraintSolver.getConstraints()[1];
        Assert.assertEquals(constrain.toString(), "(= bv_3 (bvadd #x0000007b bv_2))");
    }

    @Test
    public void testVisitINT_EQUAL() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_EQUAL, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_EQUAL(pcode, tmpEnv);
        BoolExpr constrain = constraintSolver.getConstraints()[0];
        Assert.assertEquals(constrain.toString(), "(= (= bv_0 bv_1) bool_2)");
    }

    @Test
    public void testVisitINT_NOTEQUAL() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_NOTEQUAL, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_NOTEQUAL(pcode, tmpEnv);
        BoolExpr constrain = constraintSolver.getConstraints()[0];
        Assert.assertTrue("(not (= (= bv_0 bv_1) bool_2))".equals(constrain.toString())
                || "(= (not (= bv_0 bv_1)) bool_2)".equals(constrain.toString()));
    }

    @Test
    public void testVisitINT_LESS() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(-1L), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_LESS, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_LESS(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Handle<BitVecSort> maxHandle = optimize.MkMaximize(
                constraintSolver.getALocExprHashMap().get(ALoc.getALoc(in[0])));
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.SATISFIABLE
        );

        long max = Long.parseLong(maxHandle.getValue().toString());
        Assert.assertEquals(max, 0xFFFFFFFEL);
        optimize.Pop();

        optimize.Push();
        Handle<BitVecSort> minHandle = optimize.MkMinimize(
                constraintSolver.getALocExprHashMap().get(ALoc.getALoc(in[0])));
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.SATISFIABLE
        );
        long min = Long.parseLong(minHandle.getValue().toString());
        Assert.assertEquals(min, 0);
        optimize.Pop();
    }

    @Test
    public void testVisitINT_SLESS() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(-1L), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_SLESS, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_SLESS(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Handle<BitVecSort> maxHandle = optimize.MkMaximize(
                constraintSolver.getALocExprHashMap().get(ALoc.getALoc(in[0])));
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.SATISFIABLE
        );

        long max = Long.parseLong(maxHandle.getValue().toString());
        Assert.assertEquals(max, 0xFFFFFFFEL);
        optimize.Pop();

        optimize.Push();
        Handle<BitVecSort> minHandle = optimize.MkMinimize(
                constraintSolver.getALocExprHashMap().get(ALoc.getALoc(in[0])));
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.SATISFIABLE
        );
        long min = Long.parseLong(minHandle.getValue().toString());
        Assert.assertEquals(min, 0x80000000L);
        optimize.Pop();
    }

    @Test
    public void testVisitINT_LESSEQUAL() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(-1L), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_LESSEQUAL, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_LESSEQUAL(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Handle<BitVecSort> maxHandle = optimize.MkMaximize(
                constraintSolver.getALocExprHashMap().get(ALoc.getALoc(in[0])));
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.SATISFIABLE
        );

        long max = Long.parseLong(maxHandle.getValue().toString());
        Assert.assertEquals(max, 0xFFFFFFFFL);
        optimize.Pop();

        optimize.Push();
        Handle<BitVecSort> minHandle = optimize.MkMinimize(
                constraintSolver.getALocExprHashMap().get(ALoc.getALoc(in[0])));
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.SATISFIABLE
        );
        long min = Long.parseLong(minHandle.getValue().toString());
        Assert.assertEquals(min, 0);
        optimize.Pop();
    }

    @Test
    public void testVisitINT_SLESSEQUAL() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(-1L), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_SLESSEQUAL, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_SLESSEQUAL(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Handle<BitVecSort> maxHandle = optimize.MkMaximize(
                constraintSolver.getALocExprHashMap().get(ALoc.getALoc(in[0])));
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.SATISFIABLE
        );

        long max = Long.parseLong(maxHandle.getValue().toString());
        Assert.assertEquals(max, 0xFFFFFFFFL);
        optimize.Pop();

        optimize.Push();
        Handle<BitVecSort> minHandle = optimize.MkMinimize(
                constraintSolver.getALocExprHashMap().get(ALoc.getALoc(in[0])));
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.SATISFIABLE
        );
        long min = Long.parseLong(minHandle.getValue().toString());
        Assert.assertEquals(min, 0x80000000L);
        optimize.Pop();
    }

    @Test
    public void testVisitINT_ZEXT() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);
        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();

        Varnode[] in1 = {new Varnode(Utils.getConstantAddress(0x2000), GlobalState.arch.getDefaultPointerSize())};
        Varnode out1 = new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.COPY, in1, out1);
        constraintSolver.visit_COPY(pcode, tmpEnv);

        Varnode[] in2 = {
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize()),
        };

        Varnode out2 = new Varnode(Utils.getUniqueAddress(0x10), 8);
        pcode = new PcodeOp(seq, PcodeOp.INT_ZEXT, in2, out2);

        constraintSolver.visit_INT_ZEXT(pcode, tmpEnv);
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(), Status.SATISFIABLE
        );
        Expr res = optimize.getModel()
                .eval(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out2)), false);
        BitVecExpr bitVecExpr = (BitVecExpr) res;
        Assert.assertEquals(bitVecExpr.getSortSize(), 64);
        optimize.Pop();
    }

    @Test
    public void testVisitINT_SEXT() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);
        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();

        Varnode[] in1 = {new Varnode(Utils.getConstantAddress(0xFFFFFFFFL), GlobalState.arch.getDefaultPointerSize())};
        Varnode out1 = new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.COPY, in1, out1);
        constraintSolver.visit_COPY(pcode, tmpEnv);

        Varnode[] in2 = {
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize()),
        };

        Varnode out2 = new Varnode(Utils.getUniqueAddress(0x10), 8);
        pcode = new PcodeOp(seq, PcodeOp.INT_ZEXT, in2, out2);

        constraintSolver.visit_INT_SEXT(pcode, tmpEnv);
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(), Status.SATISFIABLE
        );
        Expr res = optimize.getModel()
                .eval(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out2)), false);
        BitVecExpr bitVecExpr = (BitVecExpr) res;
        BigInteger expect = new BigInteger("FFFFFFFFFFFFFFFF", 16);
        BigInteger actual = new BigInteger(bitVecExpr.toString());
        Assert.assertEquals(expect, actual);
        Assert.assertEquals(bitVecExpr.getSortSize(), 64);
        optimize.Pop();
    }

    @Test
    public void testVisitINT_CARRY() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0xFFFFFFFFL), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(2L), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_CARRY, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_CARRY(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.SATISFIABLE
        );
        optimize.Pop();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkFalse())
                ), Status.UNSATISFIABLE
        );
        optimize.Pop();

        in[0] = new Varnode(Utils.getConstantAddress(1L), GlobalState.arch.getDefaultPointerSize());
        in[1] = new Varnode(Utils.getConstantAddress(1L), GlobalState.arch.getDefaultPointerSize());
        pcode = new PcodeOp(seq, PcodeOp.INT_CARRY, in, out);

        constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_CARRY(pcode, tmpEnv);
        z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();
        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.UNSATISFIABLE
        );
        optimize.Pop();

    }

    @Test
    public void testVisitINT_SCARRY() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0x7FFFFFFFL), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(2L), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_CARRY, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_SCARRY(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.SATISFIABLE
        );
        optimize.Pop();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkFalse())
                ), Status.UNSATISFIABLE
        );
        optimize.Pop();
    }

    @Test
    public void testVisitINT_SBORROW() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0x7FFFFFFFL), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(0x80000000L), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_SBORROW, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_SBORROW(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.SATISFIABLE
        );
        optimize.Pop();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkFalse())
                ), Status.UNSATISFIABLE
        );
        optimize.Pop();

        tmpEnv = new AbsEnv();
        in[0] = new Varnode(Utils.getConstantAddress(-1L), 8);
        in[1] = new Varnode(Utils.getConstantAddress(2), 8);
        out = new Varnode(Utils.getUniqueAddress(0x10), 1);
        pcode = new PcodeOp(seq, PcodeOp.INT_SBORROW, in, out);

        constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_SBORROW(pcode, tmpEnv);
        optimize = constraintSolver.getOptimize();
        optimize.Push();
        z3Context = constraintSolver.getZ3Context();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkFalse())
                ), Status.SATISFIABLE
        );
        optimize.Pop();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)), z3Context.mkTrue())
                ), Status.UNSATISFIABLE
        );
        optimize.Pop();
    }

    @Test
    public void testVisitINT_2COMP() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0xFFFFFFFFL), GlobalState.arch.getDefaultPointerSize()),
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_2COMP, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_2COMP(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkBV(1, 32))
                ), Status.SATISFIABLE
        );
        optimize.Pop();
    }

    @Test
    public void testVisitINT_NEGATE() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0x55555555L), GlobalState.arch.getDefaultPointerSize()),
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_2COMP, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_NEGATE(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkBV(0xAAAAAAAAL, 32))
                ), Status.SATISFIABLE
        );
        optimize.Pop();
    }

    @Test
    public void testVisitINT_XOR() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0x55555555L), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(0xAAAAAAAAL), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 4);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_SBORROW, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_XOR(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkBV(0xFFFFFFFFL, 32))
                ), Status.SATISFIABLE
        );
        optimize.Pop();
    }

    @Test
    public void testVisitINT_LEFT() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(1), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(32), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 4);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_SBORROW, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_LEFT(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkBV(0, 32))
                ), Status.SATISFIABLE
        );
        optimize.Pop();
    }

    @Test
    public void testVisitINT_RIGHT() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0xFFFFFFFF), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(16), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 4);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_SBORROW, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_RIGHT(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkBV(0xFFFF, 32))
                ), Status.SATISFIABLE
        );
        optimize.Pop();
    }

    @Test
    public void testVisitINT_SRIGHT() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0x80000000), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(32), GlobalState.arch.getDefaultPointerSize())
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 4);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_SBORROW, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_INT_SRIGHT(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkBV(0xFFFFFFFF, 32))
                ), Status.SATISFIABLE
        );
        optimize.Pop();
    }

    @Test
    public void testVisitPiece() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0x1122), 2),
                new Varnode(Utils.getConstantAddress(0x3344), 2)
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 4);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_SBORROW, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_PIECE(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();

        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkBV(0x11223344, 32))
                ), Status.SATISFIABLE
        );
        optimize.Pop();
    }

    @Test
    public void testVisitSubPiece() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0x11223344), 4),
                new Varnode(Utils.getConstantAddress(2), 4)
        };

        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 2);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.SUBPIECE, in, out);

        AbsEnv tmpEnv = new AbsEnv();
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_SUBPIECE(pcode, tmpEnv);
        com.microsoft.z3.Context z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkBV(0x1122, 16))
                ), Status.SATISFIABLE
        );
        optimize.Pop();

        tmpEnv = new AbsEnv();
        in[1] = new Varnode(Utils.getConstantAddress(0), 4);
        out = new Varnode(Utils.getUniqueAddress(0x10), 1);
        pcode = new PcodeOp(seq, PcodeOp.SUBPIECE, in, out);
        constraintSolver = new ConstraintSolver();
        constraintSolver.visit_SUBPIECE(pcode, tmpEnv);
        z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();

        optimize.Push();
        Assert.assertEquals(
                optimize.Check(
                        z3Context.mkEq(constraintSolver.getALocExprHashMap().get(ALoc.getALoc(out)),
                                z3Context.mkBV(0x44, 8))
                ), Status.SATISFIABLE
        );
        optimize.Pop();

    }


    @Test
    public void testVisitStoreLoad() {
        AbsEnv tmpEnv = new AbsEnv();

        Address instructionAddress = Utils.getDefaultAddress(0x1000);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0), GlobalState.arch.getDefaultPointerSize()), // addressSpaceId
                Utils.getRegVarnode("r0"),
                Utils.getRegVarnode("r1"),
        };
        Context mockContext = Mockito.mock(Context.class);
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x1000), mockContext, true);

        KSet ptrKSet = new KSet(32)
                .insert(new AbsVal(heap, 0x30));
        tmpEnv.set(ALoc.getALoc(in[1]), ptrKSet, true);

        PcodeOp pcode = new PcodeOp(seq, PcodeOp.STORE, in, null);
        // str r1, [r0]
        // ---  STORE (const, 0x0, 4) , (register, 0x20, 4) , (register, 0x24, 4)
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_STORE(pcode, tmpEnv);

        Varnode[] in1 = {
                new Varnode(Utils.getConstantAddress(0), GlobalState.arch.getDefaultPointerSize()),
                Utils.getRegVarnode("r0")
        };
        Varnode out = Utils.getRegVarnode("r2");
        PcodeOp pcode1 = new PcodeOp(seq, PcodeOp.LOAD, in1, out);
        // ldr r2, [r0]
        // (register, 0x28, 4) LOAD (const, 0x0, 4) , (register, 0x20, 4)
        constraintSolver.visit_LOAD(pcode1, tmpEnv);
        Expr actual;
        actual = constraintSolver.getALocExprHashMap().get(ALoc.getALoc(heap, 0x30, 4));
        Assert.assertEquals(actual.toString(), "bv_1");
        actual = constraintSolver.getALocExprHashMap().get(Reg.getALoc("r1"));
        Assert.assertEquals(actual.toString(), "bv_0");
        actual = constraintSolver.getALocExprHashMap().get(Reg.getALoc("r2"));
        Assert.assertEquals(actual.toString(), "bv_2");

        optimize = constraintSolver.getOptimize();
        optimize.Push();
        Expr e1 = constraintSolver.getALocExprHashMap().get(Reg.getALoc("r1"));
        Expr e2 = constraintSolver.getALocExprHashMap().get(Reg.getALoc("r2"));
        Assert.assertEquals(
                optimize.Check(constraintSolver.getZ3Context().mkEq(e1, e2)), Status.SATISFIABLE
        );
        optimize.Pop();
    }

    @Test
    public void testVisitStoreLoadConst() {
        AbsEnv tmpEnv = new AbsEnv();

        Address instructionAddress = Utils.getDefaultAddress(0x1000);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0), GlobalState.arch.getDefaultPointerSize()), // addressSpaceId
                Utils.getRegVarnode("r0"),
                new Varnode(Utils.getConstantAddress(0x11223344), GlobalState.arch.getDefaultPointerSize())
        };
        Context mockContext = Mockito.mock(Context.class);
        Heap heap = Heap.getHeap(Utils.getDefaultAddress(0x1000), mockContext, true);

        KSet ptrKSet = new KSet(32)
                .insert(new AbsVal(heap, 0x30));
        tmpEnv.set(ALoc.getALoc(in[1]), ptrKSet, true);

        PcodeOp pcode = new PcodeOp(seq, PcodeOp.STORE, in, null);
        // str 0x11223344, [r0]
        // ---  STORE (const, 0x0, 4) , (register, 0x20, 4) , (register, 0x24, 4)
        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_STORE(pcode, tmpEnv);

        Varnode[] in1 = {
                new Varnode(Utils.getConstantAddress(0), GlobalState.arch.getDefaultPointerSize()),
                Utils.getRegVarnode("r0")
        };
        Varnode out = Utils.getRegVarnode("r2");
        PcodeOp pcode1 = new PcodeOp(seq, PcodeOp.LOAD, in1, out);
        // ldr r2, [r0]
        // (register, 0x28, 4) LOAD (const, 0x0, 4) , (register, 0x20, 4)
        constraintSolver.visit_LOAD(pcode1, tmpEnv);
        z3Context = constraintSolver.getZ3Context();
        optimize = constraintSolver.getOptimize();
        Expr expr;
        expr = constraintSolver.getALocExprHashMap().get(ALoc.getALoc(heap, 0x30, 4));
        Assert.assertEquals(
                optimize.Check(z3Context.mkEq(expr, z3Context.mkBV(0x11223344L, 32))), Status.SATISFIABLE
        );


        expr = constraintSolver.getALocExprHashMap().get(Reg.getALoc("r2"));
        Assert.assertEquals(
                optimize.Check(z3Context.mkEq(expr, z3Context.mkBV(0x11223344L, 32))), Status.SATISFIABLE
        );

    }

    @Test
    public void testVisitLoad() {
        AbsEnv tmpEnv = new AbsEnv();
        Address instructionAddress = Utils.getDefaultAddress(0x1000);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0), GlobalState.arch.getDefaultPointerSize()),
                Utils.getRegVarnode("r0")
        };
        Varnode out = Utils.getRegVarnode("r1");
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.LOAD, in, out);
        // ldr r1, [r0]
        // (register, 0x24, 4) LOAD (const, 0x0, 4) , (register, 0x20, 4)

        // r0->top
        tmpEnv.set(Reg.getALoc("r0"), KSet.getTop(), true);

        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_LOAD(pcode, tmpEnv);
        assert tmpEnv.get(Reg.getALoc("r1")).isTop();
        Expr constraint = constraintSolver.getALocExprHashMap().get(Reg.getALoc("r1"));
        Assert.assertEquals(constraint.toString(), "bv_0");

        // r0->bot
        tmpEnv = new AbsEnv();
        constraintSolver = new ConstraintSolver();
        constraintSolver.visit_LOAD(pcode, tmpEnv);
        assert tmpEnv.get(Reg.getALoc("r1")).isBot();
        constraint = constraintSolver.getALocExprHashMap().get(Reg.getALoc("r1"));
        Assert.assertEquals(constraint.toString(), "bv_0");

        // ldr r1, [0x2000]
        int txId = program.startTransaction("init memory");
        MemoryBlock mem = programBuilder.createMemory(".data", "0x2000", 0x1000);
        mem.setRead(true);
        try {
            mem.putBytes(Utils.getDefaultAddress(0x2000), Utils.fromHexString("44332211"));
        } catch (MemoryAccessException e) {
            System.out.println(e);
        }
        program.endTransaction(txId, true);

        in[1] = new Varnode(Utils.getConstantAddress(0x2000), GlobalState.arch.getDefaultPointerSize());
        pcode = new PcodeOp(seq, PcodeOp.LOAD, in, out);
        // (register, 0x24, 4) LOAD (const, 0x0, 4) , (const, 0x2000, 4)
        tmpEnv = new AbsEnv();
        constraintSolver = new ConstraintSolver();
        constraintSolver.visit_LOAD(pcode, tmpEnv);
        KSet r1Kset = tmpEnv.get(Reg.getALoc("r1"));
        assert r1Kset.isSingleton();
        AbsVal absVal = r1Kset.getInnerSet().iterator().next();
        assert absVal.getValue() == 0x11223344L;

        optimize = constraintSolver.getOptimize();
        z3Context = constraintSolver.getZ3Context();
        Logging.debug(constraintSolver.getOptimize().toString());

        Expr expr = constraintSolver.getALocExprHashMap().get(Reg.getALoc("r1"));
        Assert.assertEquals(
                optimize.Check(z3Context.mkEq(expr, z3Context.mkBV(0x11223344L, 32))), Status.SATISFIABLE
        );

    }

    @Test
    public void testVisitStore() {

        AbsEnv tmpEnv = new AbsEnv();
        Address instructionAddress = Utils.getDefaultAddress(0x1000);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        // str r1, [r0]
        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0), GlobalState.arch.getDefaultPointerSize()), // addressSpaceId
                Utils.getRegVarnode("r0"),
                Utils.getRegVarnode("r1")
        };
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.STORE, in, null);

        // r0-> TOP
        tmpEnv.set(Reg.getALoc("r0"), KSet.getTop(), true);
        KSet r1KSet = new KSet(32).insert(new AbsVal(0x11223344L));
        tmpEnv.set(Reg.getALoc("r1"), r1KSet, true);

        ConstraintSolver constraintSolver = new ConstraintSolver();
        constraintSolver.visit_STORE(pcode, tmpEnv);
        KSet r0KSet = tmpEnv.get(Reg.getALoc("r0"));
        assert r0KSet.isTop();
        // generate no constraint.
        assert constraintSolver.getConstraints().length == 0;

        // r0 -> BOT
        tmpEnv = new AbsEnv();
        constraintSolver = new ConstraintSolver();
        constraintSolver.visit_STORE(pcode, tmpEnv);
        // generate no constraint.
        assert constraintSolver.getConstraints().length == 0;

        // str r1, [0x3000]
        // r1->[(Global, 0x11223344)]
        int txId = program.startTransaction("init memory");
        MemoryBlock mem = programBuilder.createMemory(".data", "0x3000", 0x1000);
        mem.setWrite(true);
        program.endTransaction(txId, true);

        in[1] = new Varnode(Utils.getConstantAddress(0x3000), GlobalState.arch.getDefaultPointerSize());
        pcode = new PcodeOp(seq, PcodeOp.STORE, in, null);
        constraintSolver = new ConstraintSolver();
        r1KSet = new KSet(32).insert(new AbsVal(0x11223344L));
        tmpEnv.set(Reg.getALoc("r1"), r1KSet, true);
        constraintSolver.visit_STORE(pcode, tmpEnv);

        optimize = constraintSolver.getOptimize();
        z3Context = constraintSolver.getZ3Context();
        KSet actual = tmpEnv.get(ALoc.getALoc(Global.getInstance(), 0x3000, GlobalState.arch.getDefaultPointerSize()));
        Assert.assertEquals(actual, r1KSet);

        Expr expr1 = constraintSolver.getALocExprHashMap().get(Reg.getALoc("r1"));
        Expr expr2 = constraintSolver.getALocExprHashMap().get(ALoc.getALoc(Global.getInstance(), 0x3000, 4));
        Assert.assertEquals(
                optimize.Check(z3Context.mkEq(expr1, expr2)), Status.SATISFIABLE
        );

    }

}



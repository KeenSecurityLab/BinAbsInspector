package com.bai.solver;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.Interval;
import com.bai.env.KSet;
import com.bai.env.region.Global;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import com.microsoft.z3.BitVecExpr;
import com.microsoft.z3.BoolExpr;
import com.microsoft.z3.Expr;
import com.microsoft.z3.IntExpr;
import com.microsoft.z3.IntSort;
import com.microsoft.z3.Optimize;
import com.microsoft.z3.Optimize.Handle;
import com.microsoft.z3.Params;
import com.microsoft.z3.Status;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;

public class ConstraintSolver {

    private com.microsoft.z3.Context z3Ctx;
    private Optimize optimize;
    private HashMap<ALoc, Expr> aLocExprHashMap;
    private int symbolNum = 0;
    private Context context;

    public ConstraintSolver() {
        Map<String, String> config = Map.of("model", "true");
        z3Ctx = new com.microsoft.z3.Context(config);
        optimize = z3Ctx.mkOptimize();
        Params params = z3Ctx.mkParams();
        params.add("timeout", GlobalState.config.getZ3TimeOut());
        optimize.setParameters(params);
        aLocExprHashMap = new HashMap<>();
    }

    public com.microsoft.z3.Context getZ3Context() {
        return z3Ctx;
    }

    public void initialize(AddressRange addressRange, Context context) {
        this.context = context;
        Address cur = addressRange.getMinAddress();
        while (cur.getOffset() <= addressRange.getMaxAddress().getOffset()) {
            AbsEnv tmpEnv = new AbsEnv(context.getValueBefore(cur));
            PcodeOp[] opCodes = GlobalState.flatAPI.getInstructionAt(cur).getPcode();
            Logging.debug("Address: " + cur + ": " + GlobalState.flatAPI.getInstructionAt(cur));
            // forget unique Expr before process next instruction
            aLocExprHashMap.keySet().removeIf(aloc -> aloc.getRegion().isUnique());
            for (PcodeOp opCode : opCodes) {
                visit(opCode, tmpEnv);
            }
            cur = GlobalState.flatAPI.getInstructionAfter(cur).getAddress();
        }
    }

    @SuppressWarnings("unchecked")
    private void solveBoolExprBound(ALoc aLoc, BoolExpr boolExpr, Map<ALoc, Interval> aLocBoundMap) {
        boolean hasTrue = false;
        boolean hasFalse = false;
        optimize.Push();
        optimize.Add(z3Ctx.mkEq(boolExpr, z3Ctx.mkTrue()));
        Status status = optimize.Check();
        if (status.equals(Status.SATISFIABLE)) {
            hasTrue = true;
        }
        optimize.Pop();

        optimize.Push();
        optimize.Add(z3Ctx.mkEq(boolExpr, z3Ctx.mkFalse()));
        status = optimize.Check();
        if (status.equals(Status.SATISFIABLE)) {
            hasFalse = true;
        }
        optimize.Pop();

        Interval res;
        if (hasTrue && hasFalse) {
            res = Interval.UNKNOWN;
        } else if (hasTrue && !hasFalse) {
            res = Interval.TRUE;
        } else if (!hasTrue && hasFalse) {
            res = Interval.FALSE;
        } else {
            res = Interval.UNKNOWN;
        }
        Logging.debug("Found " + aLoc + "@" + boolExpr + ": " + res);
        aLocBoundMap.put(aLoc, res);
    }

    private long getDefaultUpperBound(ALoc aLoc) {
        assert aLoc.getLen() <= 8;
        if (aLoc.isFlag()) {
            return 1L;
        } else {
            int bits = aLoc.getLen() * 8;
            return bits == 64 ? Long.MAX_VALUE : (1L << (bits - 1)) - 1;
        }
    }

    private long getDefaultLowerBound(ALoc aLoc) {
        assert aLoc.getLen() <= 8;
        if (aLoc.isFlag()) {
            return 0L;
        } else {
            int bits = aLoc.getLen() * 8;
            return bits == 64 ? Long.MIN_VALUE : (1L << (bits - 1));
        }
    }

    private BigInteger getDefaultUpperBoundBig(ALoc aLoc) {
        assert aLoc.getLen() > 8;
        if (aLoc.isFlag()) {
            return BigInteger.ONE;
        } else {
            int bits = aLoc.getLen() * 8;
            return BigInteger.ONE.shiftLeft(bits - 1).subtract(BigInteger.ONE);
        }
    }

    private BigInteger getDefaultLowerBoundBig(ALoc aLoc) {
        assert aLoc.getLen() > 8;
        if (aLoc.isFlag()) {
            return BigInteger.ZERO;
        } else {
            int bits = aLoc.getLen() * 8;
            return BigInteger.ONE.shiftLeft(bits - 1);
        }
    }

    @SuppressWarnings("unchecked")
    private void solveBVExprBound(ALoc aLoc, BitVecExpr bitVecExpr, Map<ALoc, Interval> aLocBoundMap) {
        long lowerBound;
        long upperBound;

        optimize.Push();
        Handle<IntSort> maxHandle = optimize.MkMaximize(z3Ctx.mkBV2Int(bitVecExpr, true));
        Status status = optimize.Check();
        if (status.equals(Status.SATISFIABLE)) {
            upperBound = Long.parseLong(maxHandle.toString());
            Logging.debug(
                    "[SAT] Found upper bound for " + aLoc + "@" + bitVecExpr + ": " + Long.toHexString(upperBound));
        } else {
            Logging.debug("[UNSAT] No upper bound found for " + aLoc + "@" + bitVecExpr);
            upperBound = getDefaultUpperBound(aLoc);
        }
        optimize.Pop();

        optimize.Push();
        Handle<IntSort> minHandle = optimize.MkMinimize(z3Ctx.mkBV2Int(bitVecExpr, true));
        if (optimize.Check().equals(Status.SATISFIABLE)) {
            lowerBound = Long.parseLong(minHandle.toString());
            Logging.debug(
                    "[SAT] Found lower bound for " + aLoc + "@" + bitVecExpr + ": " + Long.toHexString(lowerBound));
        } else {
            Logging.debug("[UNSAT] No lower bound found for " + aLoc + "@" + bitVecExpr);
            lowerBound = getDefaultLowerBound(aLoc);
        }
        optimize.Pop();
        Interval res = Interval.of(lowerBound, upperBound);
        Logging.debug("Found " + aLoc + "@" + bitVecExpr + ": " + res);
        aLocBoundMap.put(aLoc, res);
    }

    @SuppressWarnings("unchecked")
    private void solveBVExprBoundBig(ALoc aLoc, BitVecExpr bitVecExpr, Map<ALoc, Interval> aLocBoundMap) {
        BigInteger lowerBoundBig;
        BigInteger upperBoundBig;

        optimize.Push();
        Handle<IntSort> maxHandle = optimize.MkMaximize(z3Ctx.mkBV2Int(bitVecExpr, true));
        Status status = optimize.Check();
        if (status.equals(Status.SATISFIABLE)) {
                upperBoundBig = new BigInteger(maxHandle.toString());
                Logging.debug(
                        "[SAT] Found upper bound for " + aLoc + "@" + bitVecExpr + ": " + upperBoundBig.toString(16));
        } else {
            Logging.debug("[UNSAT] No upper bound found for " + aLoc + "@" + bitVecExpr);
            upperBoundBig = getDefaultUpperBoundBig(aLoc);
        }
        optimize.Pop();

        optimize.Push();
        Handle<IntSort> minHandle = optimize.MkMinimize(z3Ctx.mkBV2Int(bitVecExpr, true));
        if (optimize.Check().equals(Status.SATISFIABLE)) {
                lowerBoundBig = new BigInteger(minHandle.toString());
                Logging.debug(
                        "[SAT] Found lower bound for " + aLoc + "@" + bitVecExpr + ": " + lowerBoundBig.toString(16));
        } else {
            Logging.debug("[UNSAT] No lower bound found for " + aLoc + "@" + bitVecExpr);
            lowerBoundBig = getDefaultLowerBoundBig(aLoc);
        }
        optimize.Pop();
        Interval res = Interval.of(lowerBoundBig, upperBoundBig);
        Logging.debug("Found " + aLoc + "@" + bitVecExpr + ": " + res);
        aLocBoundMap.put(aLoc, res);
    }

    public Map<ALoc, Interval> solveBounds(Address address, boolean condition) {
        PcodeOp[] opCodes = GlobalState.flatAPI.getInstructionAt(address).getPcode();
        PcodeOp cbranchPcode = opCodes[opCodes.length - 1];
        HashMap<ALoc, Interval> aLocBoundMap = new HashMap<>();
        if (cbranchPcode.getOpcode() != PcodeOp.CBRANCH) {
            Logging.error("Last pcode in instruction is not CBRANCH!");
            return aLocBoundMap;
        }

        Logging.debug("Solving bounds at: " + address.toString() + " with condition " + condition);
        Logging.debug(cbranchPcode.toString());
        Varnode conditionVarnode = cbranchPcode.getInput(1);
        BoolExpr conditionExpr = getBoolExprUse(conditionVarnode);
        BoolExpr targetExpr = z3Ctx.mkEq(conditionExpr, z3Ctx.mkBool(condition));

        optimize.Push();
        addConstraint(targetExpr);
        for (Map.Entry<ALoc, Expr> entry : aLocExprHashMap.entrySet()) {
            ALoc aLoc = entry.getKey();

            if (aLoc.getRegion().isUnique()) {
                continue;
            }
            Expr expr = entry.getValue();
            if (expr.isBool()) {
                solveBoolExprBound(aLoc, (BoolExpr) expr, aLocBoundMap);
            } else if (expr.isBV()) {
                if (aLoc.getLen() <= 8) {
                    solveBVExprBound(aLoc, (BitVecExpr) expr, aLocBoundMap);
                } else {
                    solveBVExprBoundBig(aLoc, (BitVecExpr) expr, aLocBoundMap);
                }
            }
        }
        optimize.Pop();
        return aLocBoundMap;
    }

    public void printBoundMap(Map<ALoc, Interval> map) {
        for (Map.Entry<ALoc, Interval> entry : map.entrySet()) {
            ALoc aloc = entry.getKey();
            Logging.debug(aloc + "@" + aLocExprHashMap.get(aloc) + ": " + entry.getValue());
        }
    }

    public BoolExpr[] getConstraints() {
        return optimize.getAssertions();
    }

    public Optimize getOptimize() {
        return optimize;
    }

    public HashMap<ALoc, Expr> getALocExprHashMap() {
        return aLocExprHashMap;
    }

    private BoolExpr getBoolExprDef(ALoc aloc) {
        Expr res = z3Ctx.mkBoolConst("bool_" + symbolNum);
        aLocExprHashMap.put(aloc, res);
        symbolNum++;
        return (BoolExpr) res;
    }

    private BoolExpr getBoolExprDef(Varnode varnode) {
        if (varnode.isConstant()) {
            return varnode.getOffset() == 0 ? z3Ctx.mkFalse() : z3Ctx.mkTrue();
        }
        ALoc aloc = ALoc.getALoc(varnode);
        return getBoolExprDef(aloc);
    }

    private BoolExpr getBoolExprUse(ALoc aloc) {
        Expr expr = aLocExprHashMap.get(aloc);
        if (expr != null) {
            if (expr.isBV()) {
                BoolExpr res = getBoolExprDef(aloc);
                addConstraint(z3Ctx.mkIff(
                        z3Ctx.mkEq(expr, z3Ctx.mkBV(1, aloc.getLen() * 8)),
                        z3Ctx.mkEq(res, z3Ctx.mkTrue())));
                addConstraint(z3Ctx.mkIff(
                        z3Ctx.mkEq(expr, z3Ctx.mkBV(0, aloc.getLen() * 8)),
                        z3Ctx.mkEq(res, z3Ctx.mkFalse())));
                return res;
            }
            return (BoolExpr) expr;
        }
        return getBoolExprDef(aloc);
    }

    private BoolExpr getBoolExprUse(Varnode varnode) {
        if (varnode.isConstant()) {
            return varnode.getOffset() == 0 ? z3Ctx.mkBool(false) : z3Ctx.mkBool(true);
        }
        ALoc aloc = ALoc.getALoc(varnode);
        return getBoolExprUse(aloc);
    }

    private IntExpr getIntExpr(ALoc aloc) {
        Expr res;
        res = z3Ctx.mkIntConst("int_" + symbolNum);
        aLocExprHashMap.put(aloc, res);
        symbolNum++;
        return (IntExpr) res;
    }

    private IntExpr getIntExprDef(Varnode varnode) {
        if (varnode.isConstant()) {
            return z3Ctx.mkInt(varnode.getOffset());
        }
        ALoc aloc = ALoc.getALoc(varnode);
        return getIntExpr(aloc);
    }

    private IntExpr getIntExprUse(Varnode varnode) {
        if (varnode.isConstant()) {
            return z3Ctx.mkInt(varnode.getOffset());
        }
        ALoc aloc = ALoc.getALoc(varnode);
        Expr expr = aLocExprHashMap.get(aloc);
        if (expr != null) {
            return (IntExpr) expr;
        }
        return getIntExpr(aloc);
    }

    private BitVecExpr getBVExprDef(ALoc aloc) {
        Expr res = z3Ctx.mkBVConst("bv_" + symbolNum, aloc.getLen() * 8);
        aLocExprHashMap.put(aloc, res);
        symbolNum++;
        return (BitVecExpr) res;
    }

    private BitVecExpr getBVExprDef(Varnode varnode) {
        if (varnode.isConstant()) {
            return z3Ctx.mkBV(varnode.getOffset(), varnode.getSize() * 8);
        }
        ALoc aloc = ALoc.getALoc(varnode);
        return getBVExprDef(aloc);
    }

    private BitVecExpr getBVExprUse(ALoc aloc) {
        Expr expr = aLocExprHashMap.get(aloc);
        if (expr != null) {
            if (expr.isBool()) {
                BitVecExpr res = getBVExprDef(aloc);
                addConstraint(z3Ctx.mkIff(
                        z3Ctx.mkEq(expr, z3Ctx.mkTrue()),
                        z3Ctx.mkEq(res, z3Ctx.mkBV(1, aloc.getLen() * 8))));
                addConstraint(z3Ctx.mkIff(
                        z3Ctx.mkEq(expr, z3Ctx.mkFalse()),
                        z3Ctx.mkEq(res, z3Ctx.mkBV(0, aloc.getLen() * 8))));
                return res;
            }
            return (BitVecExpr) expr;
        }
        return getBVExprDef(aloc);
    }

    private BitVecExpr getBVExprUse(Varnode varnode) {
        if (varnode.isConstant()) {
            return z3Ctx.mkBV(varnode.getOffset(), varnode.getSize() * 8);
        }
        ALoc aloc = ALoc.getALoc(varnode);
        return getBVExprUse(aloc);
    }

    @SuppressWarnings("unchecked")
    private void addConstraint(BoolExpr expr) {
        BoolExpr simplified = (BoolExpr) expr.simplify();
        Logging.debug("      " + simplified.toString());
        optimize.Add(simplified);
    }

    private KSet getKSet(Varnode src, AbsEnv tmpEnv) {
        if (src.isConstant()) {
            return new KSet(src.getSize() * 8)
                    .insert(new AbsVal(Global.getInstance(), src.getOffset()));
        }
        ALoc srcALoc = ALoc.getALoc(src);
        return tmpEnv.get(srcALoc);
    }

    private void setKSet(Varnode dst, KSet srcKSet, AbsEnv tmpEnv) {
        ALoc dstALoc = ALoc.getALoc(dst);
        tmpEnv.set(dstALoc, srcKSet, true);
    }

    private boolean isBool(Expr expr) {
        return (expr != null && expr.isBool());
    }

    public void visit_COPY(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode src = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        ALoc srcALoc = ALoc.getALoc(src);
        Expr expr = aLocExprHashMap.get(srcALoc);
        if (isBool(expr)) {
            BoolExpr srcExpr = getBoolExprUse(src);
            BoolExpr dstExpr = getBoolExprDef(dst);
            addConstraint(z3Ctx.mkEq(dstExpr, srcExpr));
        } else {
            BitVecExpr srcExpr = getBVExprUse(src);
            BitVecExpr dstExpr = getBVExprDef(dst);
            addConstraint(z3Ctx.mkEq(dstExpr, srcExpr));
        }
        KSet srcKSet = getKSet(src, tmpEnv);
        setKSet(dst, srcKSet, tmpEnv);
    }

    public void visit_LOAD(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode addressSpaceId = pcode.getInput(0);
        assert addressSpaceId.isConstant();

        Varnode src = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        final BitVecExpr dstExpr = getBVExprDef(dst);

        KSet srcPtrKSet = getKSet(src, tmpEnv);
        KSet newSrcKSet = new KSet(dst.getSize() * 8);
        if (!srcPtrKSet.isNormal()) {
            // update KSet
            if (srcPtrKSet.isTop()) {
                setKSet(dst, KSet.getTop(), tmpEnv);
            }
            if (srcPtrKSet.isBot()) {
                setKSet(dst, newSrcKSet, tmpEnv);
            }
            return;
        }

        // only consider singleton
        if (!srcPtrKSet.isSingleton()) {
            return;
        }
        AbsVal ptr = srcPtrKSet.getInnerSet().iterator().next();
        if (ptr.isBigVal()) {
            return;
        }
        if (!Utils.adjustLocalAbsVal(ptr, context, srcPtrKSet.getBits()).isEmpty()) {
            // skip adjusted case, because we do not support solving inter-procedural constraints
            return;
        }
        // update KSet
        ALoc aLoc = ALoc.getALoc(ptr.getRegion(), ptr.getValue(), dst.getSize());
        KSet srcKSet = tmpEnv.get(aLoc);

        // update constraints
        Expr expr = getBVExprUse(aLoc);
        // add constraint for global read-only memory constant
        if (aLoc.isGlobalReadable() && !srcKSet.isTop() && srcKSet.iterator().hasNext()) {
            AbsVal absVal = srcKSet.iterator().next();
            if (absVal.getRegion().isGlobal() && !absVal.isBigVal()) {
                addConstraint(z3Ctx.mkEq(expr, z3Ctx.mkBV(absVal.getValue(), newSrcKSet.getBits())));
            }
        }
        setKSet(dst, srcKSet, tmpEnv);
        BoolExpr constraintsExpr = z3Ctx.mkEq(expr, dstExpr);
        addConstraint(constraintsExpr);
    }

    public void visit_STORE(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode addressSpaceId = pcode.getInput(0);
        assert addressSpaceId.isConstant();

        Varnode dst = pcode.getInput(1);
        Varnode src = pcode.getInput(2);

        final KSet srcKSet = getKSet(src, tmpEnv);
        KSet dstPtrKSet = getKSet(dst, tmpEnv);
        if (!dstPtrKSet.isNormal()) {
            return;
        }

        // only consider singleton
        if (!dstPtrKSet.isSingleton()) {
            return;
        }
        final BitVecExpr srcExpr = getBVExprUse(src);
        AbsVal ptr = dstPtrKSet.iterator().next();
        if (ptr.isBigVal()) {
            return;
        }
        if (!Utils.adjustLocalAbsVal(ptr, context, dstPtrKSet.getBits()).isEmpty()) {
            // skip adjusted case, because we do not support solving inter-procedural constraints
            return;
        }
        ALoc ptrALoc;
        if (srcKSet.isTop()) {
            ptrALoc = ALoc.getALoc(ptr.getRegion(), ptr.getValue(), dst.getSize());
        } else {
            ptrALoc = ALoc.getALoc(ptr.getRegion(), ptr.getValue(), srcKSet.getBits() / 8);
        }
        if (!ptrALoc.isGlobalWritable() && !ptrALoc.getRegion().isLocal() && !ptrALoc.getRegion().isHeap()) {
            return;
        }
        tmpEnv.set(ptrALoc, srcKSet, true);
        Expr dstExpr = getBVExprDef(ALoc.getALoc(ptr.getRegion(), ptr.getValue(), src.getSize()));
        addConstraint(z3Ctx.mkEq(srcExpr, dstExpr));
    }

    public void visit_INT_EQUAL(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BoolExpr equalExpr;
        Expr op1Expr = aLocExprHashMap.get(ALoc.getALoc(op1));
        Expr op2Expr = aLocExprHashMap.get(ALoc.getALoc(op2));

        if (isBool(op1Expr) || isBool(op2Expr)) {
            op1Expr = getBoolExprUse(op1);
            op2Expr = getBoolExprUse(op2);
            equalExpr = z3Ctx.mkEq(op1Expr, op2Expr);
        } else {
            op1Expr = getBVExprUse(op1);
            op2Expr = getBVExprUse(op2);
            equalExpr = z3Ctx.mkEq(op1Expr, op2Expr);
        }
        BoolExpr dstExpr = getBoolExprDef(dst);
        addConstraint(z3Ctx.mkIff(equalExpr, z3Ctx.mkEq(z3Ctx.mkTrue(), dstExpr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.int_equal(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_NOTEQUAL(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BoolExpr notEqualExpr;
        Expr op1Expr = aLocExprHashMap.get(ALoc.getALoc(op1));
        Expr op2Expr = aLocExprHashMap.get(ALoc.getALoc(op2));

        if (isBool(op1Expr) || isBool(op2Expr)) {
            op1Expr = getBoolExprUse(op1);
            op2Expr = getBoolExprUse(op2);
            notEqualExpr = z3Ctx.mkNot(z3Ctx.mkEq(op1Expr, op2Expr));
        } else {
            op1Expr = getBVExprUse(op1);
            op2Expr = getBVExprUse(op2);
            notEqualExpr = z3Ctx.mkNot(z3Ctx.mkEq(op1Expr, op2Expr));
        }

        BoolExpr dstExpr = getBoolExprDef(dst);
        addConstraint(z3Ctx.mkIff(notEqualExpr, z3Ctx.mkEq(z3Ctx.mkTrue(), dstExpr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = (op1KSet.int_equal(op2KSet)).bool_not();
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_LESS(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BoolExpr dstExpr = getBoolExprDef(dst);

        BoolExpr expr1 = z3Ctx.mkBVULT(op1Expr, op2Expr);
        addConstraint(z3Ctx.mkIff(expr1, z3Ctx.mkEq(z3Ctx.mkTrue(), dstExpr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.int_less(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_SLESS(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BoolExpr dstExpr = getBoolExprDef(dst);

        BoolExpr expr1 = z3Ctx.mkBVSLT(op1Expr, op2Expr);
        addConstraint(z3Ctx.mkIff(expr1, z3Ctx.mkEq(z3Ctx.mkTrue(), dstExpr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.int_sless(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_LESSEQUAL(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BoolExpr dstExpr = getBoolExprDef(dst);

        BoolExpr expr1 = z3Ctx.mkBVULE(op1Expr, op2Expr);
        addConstraint(z3Ctx.mkIff(expr1, z3Ctx.mkEq(z3Ctx.mkTrue(), dstExpr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op2KSet.int_less(op1KSet).bool_not();
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_SLESSEQUAL(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BoolExpr dstExpr = getBoolExprDef(dst);

        BoolExpr expr1 = z3Ctx.mkBVSLE(op1Expr, op2Expr);
        addConstraint(z3Ctx.mkIff(expr1, z3Ctx.mkEq(z3Ctx.mkTrue(), dstExpr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op2KSet.int_sless(op1KSet).bool_not();
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_ZEXT(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode src = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        BitVecExpr srcExpr = getBVExprUse(src);
        BitVecExpr dstExpr = getBVExprDef(dst);

        addConstraint(z3Ctx.mkEq(
                z3Ctx.mkZeroExt((dst.getSize() - src.getSize()) * 8, srcExpr),
                dstExpr));

        KSet srcKSet = getKSet(src, tmpEnv);
        KSet resKSet = srcKSet.int_zext(dst.getSize() * 8);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_SEXT(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode src = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        BitVecExpr srcExpr = getBVExprUse(src);
        BitVecExpr dstExpr = getBVExprDef(dst);

        addConstraint(z3Ctx.mkEq(
                z3Ctx.mkSignExt((dst.getSize() - src.getSize()) * 8, srcExpr),
                dstExpr));

        KSet srcKSet = getKSet(src, tmpEnv);
        KSet resKSet = srcKSet.int_sext(dst.getSize() * 8);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_ADD(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprDef(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVAdd(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.add(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_SUB(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprDef(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVSub(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.sub(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_CARRY(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BoolExpr dstExpr = getBoolExprDef(dst);

        BoolExpr expr1 = z3Ctx.mkAnd(
                z3Ctx.mkBVAddNoUnderflow(op1Expr, op2Expr),
                z3Ctx.mkBVAddNoOverflow(op1Expr, op2Expr, false)
        );
        addConstraint(z3Ctx.mkIff(expr1, z3Ctx.mkEq(z3Ctx.mkFalse(), dstExpr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.int_carry(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_SCARRY(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BoolExpr dstExpr = getBoolExprDef(dst);

        BoolExpr expr1 = z3Ctx.mkAnd(
                z3Ctx.mkBVAddNoUnderflow(op1Expr, op2Expr),
                z3Ctx.mkBVAddNoOverflow(op1Expr, op2Expr, true)
        );
        addConstraint(z3Ctx.mkIff(expr1, z3Ctx.mkEq(z3Ctx.mkFalse(), dstExpr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.int_scarry(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_SBORROW(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BoolExpr dstExpr = getBoolExprDef(dst);

        BoolExpr expr1 = z3Ctx.mkAnd(
                z3Ctx.mkBVSubNoUnderflow(op1Expr, op2Expr, true),
                z3Ctx.mkBVSubNoOverflow(op1Expr, op2Expr)
        );
        addConstraint(z3Ctx.mkIff(expr1, z3Ctx.mkEq(z3Ctx.mkFalse(), dstExpr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.int_sborrow(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_2COMP(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode src = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        BitVecExpr srcExpr = getBVExprUse(src);
        BitVecExpr dstExpr = getBVExprDef(dst);
        addConstraint(z3Ctx.mkEq(z3Ctx.mkBVNeg(srcExpr), dstExpr));

        KSet srcKSet = getKSet(src, tmpEnv);
        KSet resKSet = srcKSet.int_2comp();
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_NEGATE(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode src = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        BitVecExpr srcExpr = getBVExprUse(src);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(z3Ctx.mkBVNot(srcExpr), dstExpr));

        KSet srcKSet = getKSet(src, tmpEnv);
        KSet resKSet = srcKSet.int_negate();
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_XOR(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVXOR(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.int_xor(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_AND(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVAND(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.int_and(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_OR(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVOR(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.int_or(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_LEFT(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        if (op1.getSize() != op2.getSize()) {
            op2 = new Varnode(op2.getAddress(), op1.getSize());
        }
        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVSHL(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.lshift(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_RIGHT(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        if (op1.getSize() != op2.getSize()) {
            op2 = new Varnode(op2.getAddress(), op1.getSize());
        }
        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVLSHR(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.rshift(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_SRIGHT(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        if (op1.getSize() != op2.getSize()) {
            op2 = new Varnode(op2.getAddress(), op1.getSize());
        }
        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVASHR(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.srshift(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_MULT(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVMul(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.mult(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_DIV(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVUDiv(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.div(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_REM(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVURem(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.rem(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_SDIV(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVSDiv(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.sdiv(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_INT_SREM(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkBVSRem(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.srem(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_BOOL_NEGATE(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode dst = pcode.getOutput();

        BoolExpr op1Expr = getBoolExprUse(op1);
        BoolExpr dstExpr = getBoolExprDef(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkNot(op1Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet resKSet = op1KSet.bool_not();
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_BOOL_XOR(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BoolExpr op1Expr = getBoolExprUse(op1);
        BoolExpr op2Expr = getBoolExprUse(op2);
        BoolExpr dstExpr = getBoolExprDef(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkXor(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.bool_xor(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_BOOL_AND(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BoolExpr op1Expr = getBoolExprUse(op1);
        BoolExpr op2Expr = getBoolExprUse(op2);
        BoolExpr dstExpr = getBoolExprDef(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkAnd(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.bool_and(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_BOOL_OR(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BoolExpr op1Expr = getBoolExprUse(op1);
        BoolExpr op2Expr = getBoolExprUse(op2);
        BoolExpr dstExpr = getBoolExprDef(dst);
        addConstraint(z3Ctx.mkEq(dstExpr, z3Ctx.mkOr(op1Expr, op2Expr)));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.bool_or(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_PIECE(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr op2Expr = getBVExprUse(op2);
        BitVecExpr dstExpr = getBVExprUse(dst);

        BitVecExpr pieceExpr = z3Ctx.mkConcat(op1Expr, op2Expr);
        addConstraint(z3Ctx.mkEq(dstExpr, pieceExpr));

        KSet op1KSet = getKSet(op1, tmpEnv);
        KSet op2KSet = getKSet(op2, tmpEnv);
        KSet resKSet = op1KSet.piece(op2KSet);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit_SUBPIECE(PcodeOp pcode, AbsEnv tmpEnv) {
        Varnode op1 = pcode.getInput(0);
        Varnode op2 = pcode.getInput(1);
        Varnode dst = pcode.getOutput();

        assert op2.isConstant();

        BitVecExpr op1Expr = getBVExprUse(op1);
        BitVecExpr dstExpr = getBVExprUse(dst);

        int oldByte = op1.getSize();
        int throwByte = (int) op2.getOffset();
        int outputByte = dst.getSize();
        int leftByte = oldByte - throwByte;

        BitVecExpr subPieceExpr;
        if (outputByte <= leftByte) {
            int low = throwByte * 8;
            int high = (throwByte + outputByte) * 8 - 1;
            subPieceExpr = z3Ctx.mkExtract(high, low, op1Expr);
        } else {
            subPieceExpr = z3Ctx.mkExtract(oldByte * 8 - 1, leftByte * 8, op1Expr);
        }
        addConstraint(z3Ctx.mkEq(dstExpr, subPieceExpr));

        KSet srcKSet = getKSet(op1, tmpEnv);
        KSet byteKSet = getKSet(op2, tmpEnv);
        KSet resKSet = srcKSet.subPiece(byteKSet, dst.getSize() * 8);
        setKSet(dst, resKSet, tmpEnv);
    }

    public void visit(PcodeOp pcode, AbsEnv tmpEnv) {
        Logging.debug("    " + pcode.toString());
        switch (pcode.getOpcode()) {
            case PcodeOp.COPY:
                visit_COPY(pcode, tmpEnv);
                break;
            case PcodeOp.LOAD:
                visit_LOAD(pcode, tmpEnv);
                break;
            case PcodeOp.STORE:
                visit_STORE(pcode, tmpEnv);
                break;
            case PcodeOp.INT_EQUAL:
                visit_INT_EQUAL(pcode, tmpEnv);
                break;
            case PcodeOp.INT_NOTEQUAL:
                visit_INT_NOTEQUAL(pcode, tmpEnv);
                break;
            case PcodeOp.INT_LESS:
                visit_INT_LESS(pcode, tmpEnv);
                break;
            case PcodeOp.INT_SLESS:
                visit_INT_SLESS(pcode, tmpEnv);
                break;
            case PcodeOp.INT_LESSEQUAL:
                visit_INT_LESSEQUAL(pcode, tmpEnv);
                break;
            case PcodeOp.INT_SLESSEQUAL:
                visit_INT_SLESSEQUAL(pcode, tmpEnv);
                break;
            case PcodeOp.INT_ZEXT:
                visit_INT_ZEXT(pcode, tmpEnv);
                break;
            case PcodeOp.INT_SEXT:
                visit_INT_SEXT(pcode, tmpEnv);
                break;
            case PcodeOp.INT_ADD:
                visit_INT_ADD(pcode, tmpEnv);
                break;
            case PcodeOp.INT_SUB:
                visit_INT_SUB(pcode, tmpEnv);
                break;
            case PcodeOp.INT_CARRY:
                visit_INT_CARRY(pcode, tmpEnv);
                break;
            case PcodeOp.INT_SCARRY:
                visit_INT_SCARRY(pcode, tmpEnv);
                break;
            case PcodeOp.INT_SBORROW:
                visit_INT_SBORROW(pcode, tmpEnv);
                break;
            case PcodeOp.INT_2COMP:
                visit_INT_2COMP(pcode, tmpEnv);
                break;
            case PcodeOp.INT_NEGATE:
                visit_INT_NEGATE(pcode, tmpEnv);
                break;
            case PcodeOp.INT_XOR:
                visit_INT_XOR(pcode, tmpEnv);
                break;
            case PcodeOp.INT_AND:
                visit_INT_AND(pcode, tmpEnv);
                break;
            case PcodeOp.INT_OR:
                visit_INT_OR(pcode, tmpEnv);
                break;
            case PcodeOp.INT_LEFT:
                visit_INT_LEFT(pcode, tmpEnv);
                break;
            case PcodeOp.INT_RIGHT:
                visit_INT_RIGHT(pcode, tmpEnv);
                break;
            case PcodeOp.INT_SRIGHT:
                visit_INT_SRIGHT(pcode, tmpEnv);
                break;
            case PcodeOp.INT_MULT:
                visit_INT_MULT(pcode, tmpEnv);
                break;
            case PcodeOp.INT_DIV:
                visit_INT_DIV(pcode, tmpEnv);
                break;
            case PcodeOp.INT_REM:
                visit_INT_REM(pcode, tmpEnv);
                break;
            case PcodeOp.INT_SDIV:
                visit_INT_SDIV(pcode, tmpEnv);
                break;
            case PcodeOp.INT_SREM:
                visit_INT_SREM(pcode, tmpEnv);
                break;
            case PcodeOp.BOOL_NEGATE:
                visit_BOOL_NEGATE(pcode, tmpEnv);
                break;
            case PcodeOp.BOOL_XOR:
                visit_BOOL_XOR(pcode, tmpEnv);
                break;
            case PcodeOp.BOOL_AND:
                visit_BOOL_AND(pcode, tmpEnv);
                break;
            case PcodeOp.BOOL_OR:
                visit_BOOL_OR(pcode, tmpEnv);
                break;
            case PcodeOp.PIECE:
                visit_PIECE(pcode, tmpEnv);
                break;
            case PcodeOp.SUBPIECE:
                visit_SUBPIECE(pcode, tmpEnv);
                break;
            case PcodeOp.FLOAT_ABS:
            case PcodeOp.FLOAT_ADD:
            case PcodeOp.FLOAT_CEIL:
            case PcodeOp.FLOAT_DIV:
            case PcodeOp.FLOAT_EQUAL:
            case PcodeOp.FLOAT_FLOAT2FLOAT:
            case PcodeOp.FLOAT_FLOOR:
            case PcodeOp.FLOAT_INT2FLOAT:
            case PcodeOp.FLOAT_LESS:
            case PcodeOp.FLOAT_LESSEQUAL:
            case PcodeOp.FLOAT_MULT:
            case PcodeOp.FLOAT_NAN:
            case PcodeOp.FLOAT_NEG:
            case PcodeOp.FLOAT_NOTEQUAL:
            case PcodeOp.FLOAT_ROUND:
            case PcodeOp.FLOAT_SQRT:
            case PcodeOp.FLOAT_SUB:
            case PcodeOp.FLOAT_TRUNC:
                Logging.debug("Skipping FLOAT PCode: "
                    + pcode + " @ " + Utils.getAddress(pcode));
                break;
            default: //nothing

        }
    }
}
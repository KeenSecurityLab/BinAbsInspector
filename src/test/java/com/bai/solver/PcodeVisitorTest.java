package com.bai.solver;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.bai.Utils;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Global;
import com.bai.env.region.Local;
import com.bai.env.region.Reg;
import com.bai.env.region.Unique;
import com.bai.util.ARMProgramTestBase;
import com.bai.util.GlobalState;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.InstructionStub;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class PcodeVisitorTest extends ARMProgramTestBase {

    Function mockFunction = Mockito.mock(Function.class);
    PcodeVisitor visitor;

    @Before
    public void setUpVisitor() {
        Context context = Mockito.mock(Context.class);
        when(context.getFunction()).thenReturn(mockFunction);
        visitor = new PcodeVisitor(context);
    }

    @Test
    public void testVisitCOPY() {
        // (register, 0x8, 4) COPY (const, 0x2000, 4)
        Address instructionAddress = Utils.getDefaultAddress(0x1000);

        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);
        Varnode[] in = {new Varnode(Utils.getConstantAddress(0x2000), GlobalState.arch.getDefaultPointerSize())};
        Varnode out = new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.COPY, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();
        visitor.visit_COPY(pcode, inOutEnv, tmpEnv);
        KSet expect = new KSet(32)
                .insert(new AbsVal(Global.getInstance(), 0x2000));
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 8, 4)).equals(expect);

        // (register, 0x0, 4) COPY (register, 0x8, 4)
        in[0] = new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize());
        out = new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize());
        pcode = new PcodeOp(seq, PcodeOp.COPY, in, out);
        visitor.visit_COPY(pcode, inOutEnv, tmpEnv);
        expect = new KSet(32)
                .insert(new AbsVal(Global.getInstance(), 0x2000));
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0, 4)).equals(expect);

        // (unique, 0x4, 4) COPY (register, 0x5c, 4)
        in[0] = new Varnode(Utils.getRegisterAddress(GlobalState.arch.getPcIndex()),
                GlobalState.arch.getDefaultPointerSize());
        out = new Varnode(Utils.getUniqueAddress(0x4), GlobalState.arch.getDefaultPointerSize());
        pcode = new PcodeOp(seq, PcodeOp.COPY, in, out);
        visitor.visit_COPY(pcode, inOutEnv, tmpEnv);
        expect = new KSet(32)
                .insert(new AbsVal(Global.getInstance(), 0x1008));
        assert tmpEnv.get(ALoc.getALoc(Unique.getInstance(), 4, 4)).equals(expect);

    }

    @Test
    public void testVisitLOAD() {
        int txId = program.startTransaction("init memory");
        MemoryBlock mem = programBuilder.createMemory(".data", "0x2000", 0x1000);
        mem.setRead(true);
        try {
            mem.putBytes(Utils.getDefaultAddress(0x2000), Utils.fromHexString("44332211"));
        } catch (MemoryAccessException e) {
            System.out.println(e);
        }
        program.endTransaction(txId, true);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        Address instructionAddress = Utils.getDefaultAddress(0x1000);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        // (register, 0x8, 4) LOAD (const, 0x0, 4) , (const, 0x2000, 4)
        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(0x2000), GlobalState.arch.getDefaultPointerSize())
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.LOAD, in, out);

        visitor.visit_LOAD(pcode, inOutEnv, tmpEnv);
        KSet expect = new KSet(32).insert(new AbsVal(Global.getInstance(), 0x11223344L));
        assert inOutEnv.get(ALoc.getALoc(out)).equals(expect);

        // (register, 0x8, 4) LOAD (const, 0x0, 4) , (const, 0x2000, 4)
        out = new Varnode(Utils.getUniqueAddress(0x10), GlobalState.arch.getDefaultPointerSize());
        pcode = new PcodeOp(seq, PcodeOp.LOAD, in, out);
        visitor.visit_LOAD(pcode, inOutEnv, tmpEnv);
        expect = new KSet(32).insert(new AbsVal(Global.getInstance(), 0x11223344L));
        assert tmpEnv.get(ALoc.getALoc(out)).equals(expect);

        // LOAD TOP
        // (register, 0x24, 4) LOAD (const, 0x0, 4) , (register, 0x20, 4)
        in[1] = new Varnode(Utils.getRegisterAddress(GlobalState.currentProgram.getRegister("r0").getOffset()),
                GlobalState.arch.getDefaultPointerSize());
        out = new Varnode(Utils.getRegisterAddress(GlobalState.currentProgram.getRegister("r1").getOffset()),
                GlobalState.arch.getDefaultPointerSize());
        pcode = new PcodeOp(seq, PcodeOp.LOAD, in, out);
        ALoc r0ALoc = Reg.getALoc("r0");
        inOutEnv.set(r0ALoc, KSet.getTop(), true);
        visitor.visit_LOAD(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(r0ALoc).isTop();
        ALoc r1ALoc = Reg.getALoc("r1");
        assert inOutEnv.get(r1ALoc).isTop();
    }

    @Test
    public void testVisitSTORE() {
        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        Address instructionAddress = Utils.getDefaultAddress(0x1000);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getConstantAddress(0), GlobalState.arch.getDefaultPointerSize()), // addressSpaceId
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()), // reg 0
                new Varnode(Utils.getConstantAddress(0x11223344L), GlobalState.arch.getDefaultPointerSize()), // value
        };
        KSet ptrKSet = new KSet(32)
                .insert(new AbsVal(Global.getInstance(), 0x3000))
                .insert(new AbsVal(Unique.getInstance(), 0x10));
        inOutEnv.set(ALoc.getALoc(in[1]), ptrKSet, true);

        PcodeOp pcode = new PcodeOp(seq, PcodeOp.STORE, in, null);
        //  ---  STORE (const, 0x0, 4) , (register, 0x0, 4) , (const, 0x11223344, 4)
        visitor.visit_STORE(pcode, inOutEnv, tmpEnv);
        KSet expect = new KSet(32).insert(new AbsVal(0x11223344L));

        assert tmpEnv.get(ALoc.getALoc(Unique.getInstance(), 0x10, 4)).equals(expect);
        assert inOutEnv.get(ALoc.getALoc(Global.getInstance(), 0x3000, 4)).equals(expect);

        // smaller size
        in[2] = new Varnode(Utils.getConstantAddress(0xAABBL), 2); // value
        inOutEnv = new AbsEnv();
        tmpEnv = new AbsEnv();
        inOutEnv.set(ALoc.getALoc(in[1]), ptrKSet, true);
        pcode = new PcodeOp(seq, PcodeOp.STORE, in, null);
        visitor.visit_STORE(pcode, inOutEnv, tmpEnv);
        expect = new KSet(16).insert(new AbsVal(0xAABBL));
        assert tmpEnv.get(ALoc.getALoc(Unique.getInstance(), 0x10, 4)).isBot();
        assert tmpEnv.get(ALoc.getALoc(Unique.getInstance(), 0x10, 2)).equals(expect);
        assert inOutEnv.get(ALoc.getALoc(Global.getInstance(), 0x3000, 4)).isBot();
        assert inOutEnv.get(ALoc.getALoc(Global.getInstance(), 0x3000, 2)).equals(expect);

        // STORE TOP
        in[1] = new Varnode(Utils.getRegisterAddress(GlobalState.currentProgram.getRegister("r0").getOffset()),
                GlobalState.arch.getDefaultPointerSize());
        in[2] = new Varnode(Utils.getRegisterAddress(GlobalState.currentProgram.getRegister("r1").getOffset()),
                GlobalState.arch.getDefaultPointerSize());
        inOutEnv.set(ALoc.getALoc(in[1]), ptrKSet, true);
        inOutEnv.set(ALoc.getALoc(in[2]), KSet.getTop(), true);
        pcode = new PcodeOp(seq, PcodeOp.STORE, in, null);
        visitor.visit_STORE(pcode, inOutEnv, tmpEnv);
        assert tmpEnv.get(ALoc.getALoc(Unique.getInstance(), 0x10, 4)).isTop();
        assert inOutEnv.get(ALoc.getALoc(Global.getInstance(), 0x3000, 4)).isTop();

    }

    @Test
    public void testVisitBRANCH() {
        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        when(mockFunction.getEntryPoint()).thenReturn(Utils.getDefaultAddress(0x1000));
        // absolute address
        Address instructionAddress = Utils.getDefaultAddress(0x1020);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);
        Varnode[] in = {
                new Varnode(Utils.getDefaultAddress(0x2000), GlobalState.arch.getDefaultPointerSize())
        };
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.BRANCH, in, null);
        visitor.visit_BRANCH(pcode, inOutEnv, tmpEnv);
        assert CFG.getCFG(mockFunction).getSuccs(instructionAddress).get(0).getOffset() == 0x2000;
        Address dstAddress = Utils.getDefaultAddress(0x2000);
        assert CFG.getCFG(mockFunction).getPreds(dstAddress).get(0).getOffset() == 0x1020L;
    }

    @Test
    public void testVisitCBRANCH() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        // absolute address
        Varnode[] in = {
                new Varnode(Utils.getDefaultAddress(0x1020), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getConstantAddress(1), 1) // TRUE
        };
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.CBRANCH, in, null);

        class CurrentInstruction extends InstructionStub {

            @Override
            public PcodeOp[] getPcode(boolean includeOverrides) {
                PcodeOp[] res = {pcode};
                return res;
            }
        }

        class FallThoughInstruction extends InstructionStub {

            @Override
            public Address getAddress() {
                return Utils.getDefaultAddress(0x1014);
            }
        }

        FlatProgramAPI mockFlatProgramAPI = Mockito.mock(FlatProgramAPI.class);
        GlobalState.flatAPI = mockFlatProgramAPI;
        when(mockFlatProgramAPI.getInstructionAt(any(Address.class))).thenReturn(new CurrentInstruction());
        when(mockFlatProgramAPI.getInstructionAfter(any(Address.class))).thenReturn(new FallThoughInstruction());
        when(mockFlatProgramAPI.getAddressFactory()).thenReturn(program.getAddressFactory());

        AbsEnv inOutEnv = new AbsEnv();

        visitor.visit_CBRANCH(pcode, inOutEnv, null);
        assert CFG.getCFG(mockFunction).getSuccs(instructionAddress).get(0).getOffset() == 0x1014;
        assert CFG.getCFG(mockFunction).getSuccs(instructionAddress).get(1).getOffset() == 0x1020;

    }

    @Test
    public void testVisitBRANCHIND() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize())
        };
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.BRANCHIND, in, null);
        class CurrentInstruction extends InstructionStub {

            @Override
            public PcodeOp[] getPcode(boolean includeOverrides) {
                PcodeOp[] res = {pcode};
                return res;
            }
        }

        FlatProgramAPI mockFlatProgramAPI = Mockito.mock(FlatProgramAPI.class);
        GlobalState.flatAPI = mockFlatProgramAPI;
        when(mockFlatProgramAPI.getInstructionAt(any(Address.class))).thenReturn(new CurrentInstruction());
        // redirect GState.flatAPI.getMemoryBlock(addr) to GState.currentProgram.getMemory().getBlock(addr)
        int[] offsets = {0x20, -0x10, -0x20, 0x100};
        for (int offset : offsets) {
            Address tmp = instructionAddress.add(offset);
            when(mockFlatProgramAPI.getMemoryBlock(tmp)).thenReturn(
                    GlobalState.currentProgram.getMemory().getBlock(tmp));
        }

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        // set register 0 to target KSet
        KSet offsetKSet = new KSet(32)
                .insert(new AbsVal(Global.getInstance(), 0x20))
                .insert(new AbsVal(Global.getInstance(), -0x10))
                .insert(new AbsVal(Global.getInstance(), -0x20)) // should skip as it exceed region bound.
                .insert(new AbsVal(Local.getLocal(mockFunction), 0x100)); // should skip

        ALoc r0ALoc = ALoc.getALoc(Reg.getInstance(), 0, program.getDefaultPointerSize());
        inOutEnv.set(r0ALoc, offsetKSet, true);
        visitor.visit_BRANCHIND(pcode, inOutEnv, tmpEnv);
        List<Address> succs = CFG.getCFG(mockFunction).getSuccs(instructionAddress);
        assert succs.contains(Utils.getDefaultAddress(0x1000));
        assert succs.contains(Utils.getDefaultAddress(0x1030));
    }

    @Test
    public void testVisitINT_EQUAL() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_EQUAL, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0x11223344));
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, GlobalState.arch.getDefaultPointerSize()), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, GlobalState.arch.getDefaultPointerSize()), k1, true);

        visitor.visit_INT_EQUAL(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 1)).isTrue();
    }

    @Test
    public void testVisitINT_NOTEQUAL() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_NOTEQUAL, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0x11223344));
        KSet k2 = new KSet(32).insert(new AbsVal(0xAABBCCDD));
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, GlobalState.arch.getDefaultPointerSize()), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, GlobalState.arch.getDefaultPointerSize()), k2, true);

        visitor.visit_INT_NOTEQUAL(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 1)).isTrue();
    }

    @Test
    public void testVisitINT_LESS() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_LESS, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0));
        KSet k2 = new KSet(32).insert(new AbsVal(0xFFFFFFFFFFFFFFFFL));
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, GlobalState.arch.getDefaultPointerSize()), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, GlobalState.arch.getDefaultPointerSize()), k2, true);

        visitor.visit_INT_LESS(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 1)).isTrue();
    }

    @Test
    public void testVisitINT_SLESS() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_SLESS, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0xFFFFFFFFFFFFFFFFL));
        KSet k2 = new KSet(32).insert(new AbsVal(0));
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, GlobalState.arch.getDefaultPointerSize()), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, GlobalState.arch.getDefaultPointerSize()), k2, true);

        visitor.visit_INT_SLESS(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 1)).isTrue();
    }

    @Test
    public void testVisitINT_LESSEQUAL() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_LESSEQUAL, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0));
        KSet k2 = new KSet(32).insert(new AbsVal(0xFFFFFFFFFFFFFFFFL));
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, GlobalState.arch.getDefaultPointerSize()), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, GlobalState.arch.getDefaultPointerSize()), k2, true);

        // less
        visitor.visit_INT_LESSEQUAL(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 1)).isTrue();

        // equal
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, GlobalState.arch.getDefaultPointerSize()), k1, true);
        visitor.visit_INT_LESSEQUAL(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 1)).isTrue();
    }

    @Test
    public void testVisitINT_SLESSEQUAL() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_LESSEQUAL, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0xFFFFFFFFFFFFFFFFL));
        KSet k2 = new KSet(32).insert(new AbsVal(0));
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, GlobalState.arch.getDefaultPointerSize()), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, GlobalState.arch.getDefaultPointerSize()), k2, true);

        // less
        visitor.visit_INT_SLESSEQUAL(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 1)).isTrue();

        // equal
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, GlobalState.arch.getDefaultPointerSize()), k1, true);
        visitor.visit_INT_SLESSEQUAL(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 1)).isTrue();
    }

    @Test
    public void testVisitINT_ZEXT() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getUniqueAddress(0), 4),
        };
        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 8);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_ZEXT, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0xAAAABBBBL));
        tmpEnv.set(ALoc.getALoc(Unique.getInstance(), 0, 4), k1, true);

        visitor.visit_INT_ZEXT(pcode, inOutEnv, tmpEnv);
        KSet expect = new KSet(64).insert(new AbsVal(0xAAAABBBBL));
        assert tmpEnv.get(ALoc.getALoc(Unique.getInstance(), 0x10, 8)).equals(expect);
    }

    @Test
    public void testVisitINT_SEXT() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getUniqueAddress(0), 2),
        };
        Varnode out = new Varnode(Utils.getUniqueAddress(0x10), 8);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_SEXT, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(16).insert(new AbsVal(0xFFFEL));
        tmpEnv.set(ALoc.getALoc(Unique.getInstance(), 0, 2), k1, true);

        visitor.visit_INT_SEXT(pcode, inOutEnv, tmpEnv);
        KSet expect = new KSet(64).insert(new AbsVal(0xFFFFFFFFFFFFFFFEL));
        assert tmpEnv.get(ALoc.getALoc(Unique.getInstance(), 0x10, 8)).equals(expect);
    }

    @Test
    public void testVisitINT_ADD() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_ADD, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0x1111L));
        KSet k2 = new KSet(32).insert(new AbsVal(0x2222L));
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, GlobalState.arch.getDefaultPointerSize()), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, GlobalState.arch.getDefaultPointerSize()), k2, true);

        KSet expect = new KSet(32).insert(new AbsVal(0x3333L));
        // add
        visitor.visit_INT_ADD(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, GlobalState.arch.getDefaultPointerSize()))
                .equals(expect);
    }

    @Test
    public void testVisitINT_SUB() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_SUB, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0x2222L));
        KSet k2 = new KSet(32).insert(new AbsVal(0x1111L));
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, GlobalState.arch.getDefaultPointerSize()), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, GlobalState.arch.getDefaultPointerSize()), k2, true);

        KSet expect = new KSet(32).insert(new AbsVal(0x1111L));
        // sub
        visitor.visit_INT_SUB(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, GlobalState.arch.getDefaultPointerSize()))
                .equals(expect);
    }

    @Test
    public void testVisitINT_LEFT() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize())
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.INT_LEFT, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0x2222L));
        KSet k2 = new KSet(32).insert(new AbsVal(16)).insert(new AbsVal(32));
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, GlobalState.arch.getDefaultPointerSize()), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, GlobalState.arch.getDefaultPointerSize()), k2, true);

        KSet expect = new KSet(32).insert(new AbsVal(0x22220000L)).insert(new AbsVal(0));
        // left
        visitor.visit_INT_LEFT(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, GlobalState.arch.getDefaultPointerSize()))
                .equals(expect);
    }

    @Test
    public void testVisitBOOL_NEGATE() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), 1),
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), 1);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.BOOL_NEGATE, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(8).insert(new AbsVal(1));

        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, 1), k1, true);

        // bool negate
        visitor.visit_BOOL_NEGATE(pcode, inOutEnv, tmpEnv);
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 1)).isFalse();
    }

    @Test
    public void testVisitPIECE() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize()),
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), 8);
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.PIECE, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0x11223344L));
        KSet k2 = new KSet(32).insert(new AbsVal(0x55667788L));

        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, 4), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, 4), k2, true);

        visitor.visit_PIECE(pcode, inOutEnv, tmpEnv);
        KSet expect = new KSet(64).insert(new AbsVal(0x1122334455667788L));
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 8)).equals(expect);
    }

    @Test
    public void testVisitSUBPIECE() {
        Address instructionAddress = Utils.getDefaultAddress(0x1010);
        SequenceNumber seq = new SequenceNumber(instructionAddress, 0);

        Varnode[] in = {
                new Varnode(Utils.getRegisterAddress(0), GlobalState.arch.getDefaultPointerSize()),
                new Varnode(Utils.getRegisterAddress(8), GlobalState.arch.getDefaultPointerSize()),
        };
        Varnode out = new Varnode(Utils.getRegisterAddress(0x10), GlobalState.arch.getDefaultPointerSize());
        PcodeOp pcode = new PcodeOp(seq, PcodeOp.SUBPIECE, in, out);

        AbsEnv inOutEnv = new AbsEnv();
        AbsEnv tmpEnv = new AbsEnv();

        KSet k1 = new KSet(32).insert(new AbsVal(0x11223344L));
        KSet k2 = new KSet(32).insert(new AbsVal(2));

        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, 4), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, 4), k2, true);

        visitor.visit_SUBPIECE(pcode, inOutEnv, tmpEnv);
        KSet expect = new KSet(32).insert(new AbsVal(0x1122L));
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 4)).equals(expect);

        inOutEnv = new AbsEnv();
        k1 = new KSet(64).insert(new AbsVal(0x1122334455667788L));
        k2 = new KSet(32).insert(new AbsVal(4)).insert(new AbsVal(6));

        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, 8), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, 4), k2, true);

        in[0] = new Varnode(Utils.getRegisterAddress(0), 8);
        in[1] = new Varnode(Utils.getRegisterAddress(8), 4);
        out = new Varnode(Utils.getRegisterAddress(0x10), 8);
        pcode = new PcodeOp(seq, PcodeOp.SUBPIECE, in, out);
        visitor.visit_SUBPIECE(pcode, inOutEnv, tmpEnv);
        expect = new KSet(64)
                .insert(new AbsVal(0x11223344L))
                .insert(new AbsVal(0x1122L));
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 8)).equals(expect);

        inOutEnv = new AbsEnv();
        k1 = new KSet(64).insert(new AbsVal(0x1122334455667788L));
        k2 = new KSet(32).insert(new AbsVal(4)).insert(new AbsVal(6));

        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 0, 8), k1, true);
        inOutEnv.set(ALoc.getALoc(Reg.getInstance(), 8, 4), k2, true);

        in[0] = new Varnode(Utils.getRegisterAddress(0), 8);
        in[1] = new Varnode(Utils.getRegisterAddress(8), 4);
        out = new Varnode(Utils.getRegisterAddress(0x10), 8);
        pcode = new PcodeOp(seq, PcodeOp.SUBPIECE, in, out);
        visitor.visit_SUBPIECE(pcode, inOutEnv, tmpEnv);
        expect = new KSet(64)
                .insert(new AbsVal(0x11223344L))
                .insert(new AbsVal(0x1122L));
        assert inOutEnv.get(ALoc.getALoc(Reg.getInstance(), 0x10, 8)).equals(expect);
    }

}

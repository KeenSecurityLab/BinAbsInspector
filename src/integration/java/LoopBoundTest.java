import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.Interval;
import com.bai.env.KSet;
import com.bai.env.region.Local;
import com.bai.env.region.Reg;
import com.bai.solver.ConstraintSolver;
import com.bai.solver.PcodeVisitor;
import com.bai.util.GlobalState;
import java.io.File;
import java.util.Map;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class LoopBoundTest {


    public static class ARM32LE extends IntegrationTestBase {

        boolean hasInit = false;

        @Before
        public void setUp() throws Exception {
            if (!hasInit) {
                String path = this.getClass().getResource("/binaries/ARM32LE/loop_bound_arm_gcc.out").getPath();
                File file = new File(path);
                prepareProgram(file);
                hasInit = true;
            }
        }

        /**
         * void loop_non_negative_inc() {
         *     for (int i = 0; i<10; i ++) {
         *         putchar('0' + i);
         *     }
         * }
         */
        @Test
        public void test_loop_non_negative_inc() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x1046c);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval r3Bounds = resMap.get(Reg.getALoc("r3"));
            Assert.assertEquals(r3Bounds.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(r3Bounds.getUpper(), 9L);

            Map<ALoc, Interval> resMap1 = constraintSolver.solveBounds(cbranchAddress, false);
            r3Bounds = resMap1.get(Reg.getALoc("r3"));
            Assert.assertEquals(r3Bounds.getLower(), 10L);
            Assert.assertEquals(r3Bounds.getUpper(), Integer.MAX_VALUE);
        }

        /**
         * void loop_non_negative_dec() {
         *     for (int i=9; i>=0; i--) {
         *         putchar('0' + i);
         *     }
         * }
         */
        @Test
        public void test_loop_non_negative_dec() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x104b8);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval r3Bounds = resMap.get(Reg.getALoc("r3"));
            Assert.assertEquals(r3Bounds.getLower(), 0L);
            Assert.assertEquals(r3Bounds.getUpper(), Integer.MAX_VALUE);

            resMap = constraintSolver.solveBounds(cbranchAddress, false);
            r3Bounds = resMap.get(Reg.getALoc("r3"));
            Assert.assertEquals(r3Bounds.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(r3Bounds.getUpper(), -1L);
        }

        /**
         * void loop_negative_inc() {
         *     for (int i=-10; i<0; i++) {
         *         putchar('9' + 1 + i);
         *     }
         * }
         */
        @Test
        public void test_loop_negative_inc() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x10504);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval r3Bounds = resMap.get(Reg.getALoc("r3"));
            Assert.assertEquals(r3Bounds.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(r3Bounds.getUpper(), -1L);

            Map<ALoc, Interval> resMap1 = constraintSolver.solveBounds(cbranchAddress, false);
            r3Bounds = resMap1.get(Reg.getALoc("r3"));
            Assert.assertEquals(r3Bounds.getLower(), 0L);
            Assert.assertEquals(r3Bounds.getUpper(), Integer.MAX_VALUE);
        }

        /**
         * void loop_negative_dec() {
         *     for (int i=-1; i>=-10; i--) {
         *         putchar('9' + 1 + i);
         *     }
         * }
         */
        @Test
        public void test_loop_negative_dec() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x10550);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval r3Bounds = resMap.get(Reg.getALoc("r3"));
            Assert.assertEquals(r3Bounds.getLower(), -10L);
            Assert.assertEquals(r3Bounds.getUpper(), Integer.MAX_VALUE);

            Map<ALoc, Interval> resMap1 = constraintSolver.solveBounds(cbranchAddress, false);
            r3Bounds = resMap1.get(Reg.getALoc("r3"));
            Assert.assertEquals(r3Bounds.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(r3Bounds.getUpper(), -11L);
        }

        /**
         * void loop_inc() {
         *     for (int i=-10; i<=10; i++) {
         *         printf("%d ", i);
         *     }
         * }
         */
        @Test
        public void test_loop_inc() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x10598);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval r3Bounds = resMap.get(Reg.getALoc("r3"));
            constraintSolver.printBoundMap(resMap);
            Assert.assertEquals(r3Bounds.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(r3Bounds.getUpper(), 10L);

            Map<ALoc, Interval> resMap1 = constraintSolver.solveBounds(cbranchAddress, false);
            r3Bounds = resMap1.get(Reg.getALoc("r3"));
            constraintSolver.printBoundMap(resMap1);
            Assert.assertEquals(r3Bounds.getLower(), 11L);
            Assert.assertEquals(r3Bounds.getUpper(), Integer.MAX_VALUE);
        }

        /**
         * void loop_dec() {
         *     for (int i=10; i>=-10; i--) {
         *         printf("%d ", i);
         *     }
         * }
         */
        @Test
        public void test_loop_dec() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x105e4);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval r3Bounds = resMap.get(Reg.getALoc("r3"));
            constraintSolver.printBoundMap(resMap);
            Assert.assertEquals(r3Bounds.getLower(), -10L);
            Assert.assertEquals(r3Bounds.getUpper(), Integer.MAX_VALUE);

            Map<ALoc, Interval> resMap1 = constraintSolver.solveBounds(cbranchAddress, false);
            r3Bounds = resMap1.get(Reg.getALoc("r3"));
            constraintSolver.printBoundMap(resMap1);
            Assert.assertEquals(r3Bounds.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(r3Bounds.getUpper(), -11);
        }
    }

    public static class X64 extends IntegrationTestBase {

        boolean hasInit = false;

        @Before
        public void setUp() throws Exception {
            if (!hasInit) {
                String path = this.getClass().getResource("/binaries/X86_64/loop_bound_x64_gcc.out").getPath();
                File file = new File(path);
                prepareProgram(file);
                hasInit = true;
            }
        }

        private ALoc setupStackVar(Address address, Function func, Context context) {
            AbsEnv absEnv = new AbsEnv();
            Local local = Local.getLocal(func);
            absEnv.set(Reg.getALoc("RBP"), new KSet(64).insert(new AbsVal(local, 0)), true);
            ALoc varALoc = ALoc.getALoc(local, -4, 4);
            absEnv.set(varALoc, new KSet(32).insert(new AbsVal(0)), true);
            Address nextAddress = GlobalState.flatAPI.getInstructionBefore(address).getAddress();
            context.setValueBefore(nextAddress, absEnv);
            return varALoc;
        }

        /**
         * void loop_non_negative_inc() {
         *     for (int i = 0; i<10; i ++) {
         *         putchar('0' + i);
         *     }
         * }
         */
        @Test
        public void test_loop_non_negative_inc() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x1006b0);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);

            ALoc varALoc = setupStackVar(cbranchAddress, mainFunction, emptyContext);
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval varBound = resMap.get(varALoc);
            Assert.assertEquals(varBound.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(varBound.getUpper(), 9L);

            Map<ALoc, Interval> resMap1 = constraintSolver.solveBounds(cbranchAddress, false);
            varBound = resMap1.get(varALoc);
            Assert.assertEquals(varBound.getLower(), 10L);
            Assert.assertEquals(varBound.getUpper(), Integer.MAX_VALUE);
        }

        /**
         * void loop_non_negative_dec() {
         *     for (int i=9; i>=0; i--) {
         *         putchar('0' + i);
         *     }
         * }
         */
        @Test
        public void test_loop_non_negative_dec() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x1006db);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);

            ALoc varALoc = setupStackVar(cbranchAddress, mainFunction, emptyContext);
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval varBound = resMap.get(varALoc);
            Assert.assertEquals(varBound.getLower(), 0);
            Assert.assertEquals(varBound.getUpper(), Integer.MAX_VALUE);

            Map<ALoc, Interval> resMap1 = constraintSolver.solveBounds(cbranchAddress, false);
            varBound = resMap1.get(varALoc);
            Assert.assertEquals(varBound.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(varBound.getUpper(), -1L);

        }

        /**
         * void loop_negative_inc() {
         *     for (int i=-10; i<0; i++) {
         *         putchar('9' + 1 + i);
         *     }
         * }
         */
        @Test
        public void test_loop_negative_inc() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x100706);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);

            ALoc varALoc = setupStackVar(cbranchAddress, mainFunction, emptyContext);
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval varBound = resMap.get(varALoc);
            Assert.assertEquals(varBound.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(varBound.getUpper(), -1L);

            Map<ALoc, Interval> resMap1 = constraintSolver.solveBounds(cbranchAddress, false);
            varBound = resMap1.get(varALoc);
            Assert.assertEquals(varBound.getLower(), 0L);
            Assert.assertEquals(varBound.getUpper(), Integer.MAX_VALUE);
        }

        /**
         * void loop_negative_dec() {
         *     for (int i=-1; i>=-10; i--) {
         *         putchar('9' + 1 + i);
         *     }
         * }
         */
        @Test
        public void test_loop_negative_dec() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x100731);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);

            ALoc varALoc = setupStackVar(cbranchAddress, mainFunction, emptyContext);
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval varBound = resMap.get(varALoc);
            Assert.assertEquals(varBound.getLower(), -10L);
            Assert.assertEquals(varBound.getUpper(), Integer.MAX_VALUE);

            Map<ALoc, Interval> resMap1 = constraintSolver.solveBounds(cbranchAddress, false);
            varBound = resMap1.get(varALoc);
            Assert.assertEquals(varBound.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(varBound.getUpper(), -11L);
        }

        /**
         * void loop_inc() {
         *     for (int i=-10; i<=10; i++) {
         *         printf("%d ", i);
         *     }
         * }
         */
        @Test
        public void test_loop_inc() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x100765);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);

            ALoc varALoc = setupStackVar(cbranchAddress, mainFunction, emptyContext);
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval varBound = resMap.get(varALoc);
            Assert.assertEquals(varBound.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(varBound.getUpper(), 10L);

            Map<ALoc, Interval> resMap1 = constraintSolver.solveBounds(cbranchAddress, false);
            varBound = resMap1.get(varALoc);
            Assert.assertEquals(varBound.getLower(), 11L);
            Assert.assertEquals(varBound.getUpper(), Integer.MAX_VALUE);
        }

        /**
         * void loop_dec() {
         *     for (int i=10; i>=-10; i--) {
         *         printf("%d ", i);
         *     }
         * }
         */
        @Test
        public void test_loop_dec() {
            Address cbranchAddress = GlobalState.flatAPI.toAddr(0x100799);
            Function mainFunction = GlobalState.flatAPI.getGlobalFunctions("main").get(0);
            Context emptyContext = Context.getEntryContext(mainFunction);

            ALoc varALoc = setupStackVar(cbranchAddress, mainFunction, emptyContext);;
            ConstraintSolver constraintSolver = new ConstraintSolver();
            constraintSolver.initialize(
                    PcodeVisitor.getConstraintBasicBlock(cbranchAddress),
                    emptyContext);

            Map<ALoc, Interval> resMap = constraintSolver.solveBounds(cbranchAddress, true);
            Interval varBound = resMap.get(varALoc);
            constraintSolver.printBoundMap(resMap);
            Assert.assertEquals(varBound.getLower(), -10L);
            Assert.assertEquals(varBound.getUpper(), Integer.MAX_VALUE);

            Map<ALoc, Interval> resMap1 = constraintSolver.solveBounds(cbranchAddress, false);
            varBound = resMap1.get(varALoc);
            constraintSolver.printBoundMap(resMap1);
            Assert.assertEquals(varBound.getLower(), Integer.MIN_VALUE);
            Assert.assertEquals(varBound.getUpper(), -11);
        }
    }


}

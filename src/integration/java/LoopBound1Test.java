import ghidra.program.model.listing.Program;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Reg;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import java.io.File;
import org.junit.Before;
import org.junit.Test;

/**
 * #include <stdlib.h>
 * #include <stdio.h>
 *
 * void loop1(int c) {
 *     for (int i=c; i<10; i++) {
 *         printf("%d\n", i);
 *     }
 * }
 *
 * void loop2()  {
 *     for (int i=0; i<10; i++) {
 *         for (int j=i; j<5; j++) {
 *             printf("%d %d\n", i, j);
 *         }
 *     }
 * }
 *
 * void func_b(int b, int c) {
 *     loop1(b);
 * }
 *
 * void func_a(int a, int b, int c) {
 *     func_b(b, c);
 * }
 *
 *
 * int main() {
 *     func_a(1, 2, 3);
 *     loop2();
 * }
 */
public class LoopBound1Test {

    public static class ARM32LE extends IntegrationTestBase {

        boolean hasInit = false;
        Program program;

        @Before
        public void setUp() throws Exception {
            if (!hasInit) {
                String path = this.getClass().getResource("/binaries/ARM32LE/loop_bound1_arm_gcc.out").getPath();
                File file = new File(path);
                program = prepareProgram(file);
                hasInit = true;
            }
        }

        @Test
        public void test_loop() {
            analyzeFromMain(program);
            for (Context ctx : Context.getPool().keySet()) {
                Logging.debug(ctx.toString());

            }

            check_loop1();
            check_loop2();
        }

        private void check_loop1() {
            Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x10400)))
                    .get(0);
            AbsEnv absEnv = context.getValueBefore(GlobalState.flatAPI.toAddr(0x10424));
            KSet r1KSet = absEnv.get(Reg.getALoc("r1"));
            Logging.debug(absEnv.toString());
            Logging.debug(r1KSet.toString());
            for (AbsVal absVal : r1KSet) {
                assert absVal.getValue() <= 9 && absVal.getValue() >= 2;
            }
        }

        private void check_loop2() {
            Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x10450)))
                    .get(0);
            AbsEnv absEnv = context.getValueBefore(GlobalState.flatAPI.toAddr(0x10480));
            KSet r1KSet = absEnv.get(Reg.getALoc("r1"));
            KSet r2KSet = absEnv.get(Reg.getALoc("r2"));
            Logging.debug(absEnv.toString());
            Logging.debug(r1KSet.toString());
            Logging.debug(r2KSet.toString());
            for (AbsVal absVal : r1KSet) {
                assert absVal.getValue() >= 0 && absVal.getValue() <= 9;
            }
            for (AbsVal absVal : r2KSet) {
                assert absVal.getValue() >= 0 && absVal.getValue() <= 4;
            }
        }
    }

    public static class X64 extends IntegrationTestBase {

        boolean hasInit = false;
        Program program;

        @Before
        public void setUp() throws Exception {
            if (!hasInit) {
                String path = this.getClass().getResource("/binaries/X86_64/loop_bound1_x64_gcc.out").getPath();
                File file = new File(path);
                program = prepareProgram(file);
                hasInit = true;
            }
        }

        @Test
        public void test_loop() {
            analyzeFromMain(program);
            for (Context ctx : Context.getPool().keySet()) {
                Logging.debug(ctx.toString());

            }

            // x64 could not solve loop1, as the constraint constant is passed by argument.
            check_loop2();
        }

        private void check_loop2() {
            Context context = Context.getContext(
                    GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x100683))).get(0);
            AbsEnv absEnv = context.getValueBefore(GlobalState.flatAPI.toAddr(0x1006b0));
            KSet rsiKSet = absEnv.get(Reg.getALoc("RSI"));
            KSet rdxKSet = absEnv.get(Reg.getALoc("RDX"));
            for (AbsVal absVal : rsiKSet) {
                assert absVal.getValue() >= 0 && absVal.getValue() <= 9;
            }
            for (AbsVal absVal : rdxKSet) {
                assert absVal.getValue() >= 0 && absVal.getValue() <= 4;
            }
        }
    }
}
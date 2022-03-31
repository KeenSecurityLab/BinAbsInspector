import static com.bai.checkers.MemoryCorruption.CWE416;

import com.bai.checkers.MemoryCorruption;
import com.bai.env.Context;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Test;

/**
 * #include <stdio.h>
 * #include <stdlib.h>
 * #include <string.h>
 *
 * #define BUFSIZE1 512
 *
 * int main(int argc, char **argv) {
 *         char *buf1R1;
 *         char *buf2R1;
 *         buf1R1 = (char *) malloc(BUFSIZE1);
 *         buf2R1 = (char *) malloc(BUFSIZE1);
 *         free(buf1R1);
 *         free(buf2R1);
 *         memset(buf1R1, 0x42, BUFSIZE1);
 *         buf2R1[0] = 0;
 *         return buf1R1[0];
 * }
 */

public class CWE416Test extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_416_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x10460)))
                .get(0);
        assert Logging.getCWEReports().size() == 3;
        long[] expectedAddressesLong = {0x104b0, 0x104bc, 0x104c4};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = new CWEReport(CWE416, MemoryCorruption.VERSION, "")
                    .setAddress(GlobalState.flatAPI.toAddr(addr))
                    .setContext(context);
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_416_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x100814)))
                .get(0);
        assert Logging.getCWEReports().size() == 3;
        long[] expectedAddressesLong = {0x100858, 0x100860, 0x100868};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = new CWEReport(CWE416, MemoryCorruption.VERSION, "")
                    .setAddress(GlobalState.flatAPI.toAddr(addr))
                    .setContext(context);
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_416_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x1006da)))
                .get(0);
        assert Logging.getCWEReports().size() == 3;
        long[] expectedAddressesLong = {0x10072e, 0x100737, 0x10073e};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = new CWEReport(CWE416, MemoryCorruption.VERSION, "")
                    .setAddress(GlobalState.flatAPI.toAddr(addr))
                    .setContext(context);
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_416_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x1120d)))
                .get(0);
        assert Logging.getCWEReports().size() == 3;
        long[] expectedAddressesLong = {0x11279, 0x11284, 0x1128a};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = new CWEReport(CWE416, MemoryCorruption.VERSION, "")
                    .setAddress(GlobalState.flatAPI.toAddr(addr))
                    .setContext(context);
            assert Logging.getCWEReports().containsValue(expect);
        }
    }
}

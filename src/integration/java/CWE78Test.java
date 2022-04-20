import com.bai.checkers.CWE78;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Test;


/**
 * #include <string.h>
 * #include <stdlib.h>
 *
 * void constant_system() {
 *     system("ls");
 * }
 *
 * int main(int argc, char **argv) {
 *     char dest[30] = "usr/bin/cat ";
 *     strcat(dest, argv[1]);
 *     system(dest);
 *     constant_system();
 *     return 0;
 * }
 */
public class CWE78Test extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_78_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        CWE78 cwe78Checker = new CWE78();
        boolean result = cwe78Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x104dc};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe78Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_78_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        CWE78 cwe78Checker = new CWE78();
        boolean result = cwe78Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x100844};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe78Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_78_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        CWE78 cwe78Checker = new CWE78();
        boolean result = cwe78Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x1129d};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe78Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_78_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        CWE78 cwe78Checker = new CWE78();
        boolean result = cwe78Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x4011a3};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe78Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    /**
     * #include <string.h>
     * #include <stdlib.h>
     * #include <stdio.h>
     *
     * // modified from juliet: CWE78_OS_Command_Injection/s02/CWE78_OS_Command_Injection__char_environment_system_01.c
     *
     * void bad() {
     *     char * data;
     *     char data_buf[100] = "ls ";
     *     data = data_buf;
     *
     *     size_t dataLen = strlen(data);
     *     char * environment = getenv("ADD");
     *     if (environment != NULL) {
     *         strncat(data+dataLen, environment, 100-dataLen-1);
     *     }
     *     if (system(data)!=0) {
     *         puts("command execution failed!");
     *         exit(1);
     *     }
     * }
     *
     * int main(int argc, char **argv) {
     *     bad();
     * }
     */
    @Test
    public void test_getenv_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_78_getenv_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        CWE78 cwe78Checker = new CWE78();
        boolean result = cwe78Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x105a4};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe78Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_getenv_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_78_getenv_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        CWE78 cwe78Checker = new CWE78();
        boolean result = cwe78Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x100964};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe78Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_getenv_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_78_getenv_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        CWE78 cwe78Checker = new CWE78();
        boolean result = cwe78Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x112d5};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe78Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_getenv_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_78_getenv_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        CWE78 cwe78Checker = new CWE78();
        boolean result = cwe78Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x40124b};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe78Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }
}

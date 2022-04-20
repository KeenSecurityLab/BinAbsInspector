import com.bai.checkers.CWE426;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Test;

/**
 * #define _GNU_SOURCE
 *
 * #include <stdlib.h>
 * #include <unistd.h>
 * #include <string.h>
 * #include <sys/types.h>
 * #include <stdio.h>
 *
 * void vulnerable_sub(){
 *   gid_t gid;
 *   uid_t uid;
 *   gid = getegid();
 *   uid = geteuid();
 *
 *   setresgid(gid, gid, gid);
 *   setresuid(uid, uid, uid);
 *
 *   system("/usr/bin/env echo and now what?");
 * }
 *
 * int main(int argc, char **argv, char **envp)
 * {
 *   vulnerable_sub();
 * }
 */
public class CWE426Test extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_426_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE426 cwe426Checker = new CWE426();
        boolean result = cwe426Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x10510};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe426Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_path_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_426_path_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE426 cwe426Checker = new CWE426();
        boolean result = cwe426Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 3;
        long[] expectedAddressesLong = {0x105f4, 0x1069c, 0x1066c};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe426Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_426_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE426 cwe426Checker = new CWE426();
        boolean result = cwe426Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x100914};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe426Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_path_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_426_path_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE426 cwe426Checker = new CWE426();
        boolean result = cwe426Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 3;
        long[] expectedAddressesLong = {0x1007ec, 0x100850, 0x100874};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe426Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_426_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE426 cwe426Checker = new CWE426();
        boolean result = cwe426Checker.check();
        assert result;
        long[] expectedAddressesLong = {0x1007ad};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe426Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_426_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE426 cwe426Checker = new CWE426();
        boolean result = cwe426Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x11281};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe426Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_path_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_426_path_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE426 cwe426Checker = new CWE426();
        boolean result = cwe426Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 3;
        long[] expectedAddressesLong = {0x11221, 0x11287, 0x112b4};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe426Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_path_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_426_path_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE426 cwe426Checker = new CWE426();
        boolean result = cwe426Checker.check();
        assert result;
        long[] expectedAddressesLong = {0x1007a7, 0x10071c, 0x10077d};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe426Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }
}

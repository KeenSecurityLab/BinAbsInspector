import com.bai.checkers.CWE134;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Test;

/**
 * #include <stdio.h>
 *
 * int main(int argc, char **argv) {
 *      char buf[128];
 *      snprintf(buf,128,argv[1]);
 *      return 0;
 * }
 */
public class CWE134Test extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_134_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE134 cwe134Checker = new CWE134();
        boolean result = cwe134Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x1042c};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe134Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_134_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE134 cwe134Checker = new CWE134();
        boolean result = cwe134Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x1007bc};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe134Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_134_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE134 cwe134Checker = new CWE134();
        boolean result = cwe134Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x100681};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe134Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_134_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        CWE134 cwe134Checker = new CWE134();
        boolean result = cwe134Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x11225};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe134Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }
}

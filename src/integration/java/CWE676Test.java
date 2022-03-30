import com.bai.checkers.CWE676;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Test;

/**
 *  #include <stdio.h>
 *  #include <string.h>
 *
 *  int main ()
 *  {
 *      char str1[]="Hello World!";
 *      char str2[40];
 *      strcpy (str2,str1);
 *      return 0;
 *  }
 */
public class CWE676Test extends IntegrationTestBase {
    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_676_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE676 cwe676Checker = new CWE676();
        boolean result = cwe676Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x10430};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe676Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_676_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE676 cwe676Checker = new CWE676();
        boolean result = cwe676Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x1007c0};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe676Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_676_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE676 cwe676Checker = new CWE676();
        boolean result = cwe676Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x100679};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe676Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_676_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE676 cwe676Checker = new CWE676();
        boolean result = cwe676Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x1122f};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe676Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }
}

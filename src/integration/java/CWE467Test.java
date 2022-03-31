import com.bai.checkers.CWE467;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Test;

public class CWE467Test extends IntegrationTestBase {
    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_467_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE467 cwe467Checker = new CWE467();
        boolean result = cwe467Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 2;
        long[] expectedAddressesLong = {0x104d4, 0x10508};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe467Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_467_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE467 cwe467Checker = new CWE467();
        boolean result = cwe467Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 2;
        long[] expectedAddressesLong = {0x1008d8, 0x10090c};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe467Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_467_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE467 cwe467Checker = new CWE467();
        boolean result = cwe467Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 2;
        long[] expectedAddressesLong = {0x10079c, 0x1007ce};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe467Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_467_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE467 cwe467Checker = new CWE467();
        boolean result = cwe467Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 2;
        long[] expectedAddressesLong = {0x11266, 0x1129a};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe467Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }
}

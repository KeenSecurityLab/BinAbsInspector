import com.bai.checkers.CWE190;
import com.bai.checkers.IntegerOverflowUnderflow;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Test;

public class CWE190Test extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_190_arm_gcc.out").getPath();
        File file = new File(path);
        prepareProgram(file);
        CWE190 cwe190Checker = new CWE190();
        boolean result = cwe190Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 3;
        long[] expectedAddressesLong = {0x10690, 0x10548, 0x10720};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe190Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_fscanf_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_190_fscanf_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        long[] expectedAddressesLong = {0x104dc, 0x10534, 0x10598, 0x1059c};
        for (long addr: expectedAddressesLong) {
            CWEReport expect = new CWEReport(IntegerOverflowUnderflow.CWE190, IntegerOverflowUnderflow.VERSION, "")
                    .setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_190_armv8_gcc.out").getPath();
        File file = new File(path);
        prepareProgram(file);
        CWE190 cwe190Checker = new CWE190();
        boolean result = cwe190Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 3;
        long[] expectedAddressesLong = {0x10093c, 0x100a58, 0x100ac8};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe190Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_190_x64_gcc.out").getPath();
        File file = new File(path);
        prepareProgram(file);
        CWE190 cwe190Checker = new CWE190();
        boolean result = cwe190Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 3;
        long[] expectedAddressesLong = {0x10082c, 0x100913, 0x100986};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe190Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_190_x32_gcc.out").getPath();
        File file = new File(path);
        prepareProgram(file);
        CWE190 cwe190Checker = new CWE190();
        boolean result = cwe190Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 3;
        long[] expectedAddressesLong = {0x1126f, 0x11377, 0x11401};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe190Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }

    }
}
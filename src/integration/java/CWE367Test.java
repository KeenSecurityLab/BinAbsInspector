import com.bai.checkers.CWE367;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Test;

/**
 * #include <stdio.h>
 * #include <stdlib.h>
 * #include <sys/types.h>
 * #include <unistd.h>
 * #include <fcntl.h>
 * #include <string.h>
 *
 * int main(){
 *
 *   if (access("file", W_OK) != 0) {
 *     exit(1);
 *   }
 *
 *   char* buffer = malloc(6);
 *   if(buffer == NULL){
 *     exit(1);
 *   }
 *   memset(buffer, 1, 6);
 *
 *   int fd = open("file", O_WRONLY);
 *   write(fd, buffer, sizeof(buffer));
 *
 *   close(fd);
 *   free(buffer);
 * }
 */
public class CWE367Test extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_367_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE367 cwe367Checker = new CWE367();
        boolean result = cwe367Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x105b8};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe367Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_367_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE367 cwe367Checker = new CWE367();
        boolean result = cwe367Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x1009f8};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe367Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_367_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE367 cwe367Checker = new CWE367();
        boolean result = cwe367Checker.check();
        assert result;
        long[] expectedAddressesLong = {0x1008a7};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe367Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_367_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        // Run only particular checker here
        CWE367 cwe367Checker = new CWE367();
        boolean result = cwe367Checker.check();
        assert result;
        assert Logging.getCWEReports().size() == 1;
        long[] expectedAddressesLong = {0x112da};
        for (long addr : expectedAddressesLong) {
            CWEReport expect = cwe367Checker.getNewReport("").setAddress(GlobalState.flatAPI.toAddr(addr));
            assert Logging.getCWEReports().containsValue(expect);
        }
    }
}

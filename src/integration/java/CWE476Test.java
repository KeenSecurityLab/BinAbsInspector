import com.bai.checkers.MemoryCorruption;
import com.bai.env.Context;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Test;

/**
 * #include <stdlib.h>
 * #include <stdio.h>
 *
 * typedef struct _twoIntsStruct
 * {
 *     int intOne;
 *     int intTwo;
 * } twoIntsStruct;
 *
 * void printIntLine(int intNumber) {
 *     printf("%d\n", intNumber);
 * }
 *
 * int main() {
 *     twoIntsStruct * data;
 *     data = NULL;
 *     printIntLine(data->intOne);
 * }
 */

public class CWE476Test extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_476_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);

        Address address = GlobalState.flatAPI.toAddr(0x10444);
        Context context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("main").get(0)).get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE476, "", "").setContext(context).setAddress(address);
        assert Logging.getCWEReports().containsKey(expect);
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_476_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);

        Address address = GlobalState.flatAPI.toAddr(0x10075c);
        Context context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("main").get(0)).get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE476, "", "").setContext(context).setAddress(address);
        assert Logging.getCWEReports().containsKey(expect);
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_476_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);

        Address address = GlobalState.flatAPI.toAddr(0x100682);
        Context context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("main").get(0)).get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE476, "", "").setContext(context).setAddress(address);
        assert Logging.getCWEReports().containsKey(expect);
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_476_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);

        Address address = GlobalState.flatAPI.toAddr(0x10570);
        Context context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("main").get(0)).get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE476, "", "").setContext(context).setAddress(address);
        assert Logging.getCWEReports().containsKey(expect);
    }
}

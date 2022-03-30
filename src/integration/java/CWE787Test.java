import com.bai.checkers.MemoryCorruption;
import com.bai.env.Context;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.io.File;
import java.util.Map;
import org.junit.Test;

/**
 *  #include <stdlib.h>
 *  #include <stdio.h>
 *
 *  void set_idx(int *array, int idx, int value) {
 *     array[idx] = value;
 *  }
 *
 *  int main() {
 *     int array[5] = {1, 2, 3, 4, 5};
 *     array[25] = 100;
 *     set_idx(array, 25, 100);
 *     return 0;
 *  }
 */
public class CWE787Test extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_787_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Map<CWEReport, CWEReport> cweReportMap = Logging.getCWEReports();

        Address address = GlobalState.flatAPI.toAddr(0x10434);
        Context context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("main").get(0)).get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x103f4);
        context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("set_idx").get(0)).get(0);
        expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_787_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Map<CWEReport, CWEReport> cweReportMap = Logging.getCWEReports();

        Address address = GlobalState.flatAPI.toAddr(0x100744);
        Context context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("main").get(0)).get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x100708);
        context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("set_idx").get(0)).get(0);
        expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_787_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Map<CWEReport, CWEReport> cweReportMap = Logging.getCWEReports();

        Address address = GlobalState.flatAPI.toAddr(0x10064f);
        Context context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("main").get(0)).get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x10061f);
        context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("set_idx").get(0)).get(0);
        expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_787_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Map<CWEReport, CWEReport> cweReportMap = Logging.getCWEReports();

        Address address = GlobalState.flatAPI.toAddr(0x10544);
        Context context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("main").get(0)).get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x1050c);
        context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("set_idx").get(0)).get(0);
        expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);
    }
}

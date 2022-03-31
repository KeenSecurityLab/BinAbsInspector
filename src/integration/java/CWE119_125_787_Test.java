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
 * #include <stdlib.h>
 * #include <stdio.h>
 *
 * void set_array_elements(int* array) {
 *  for(int i = 0; i<= 10; i++) {
 *      array[i] = i*i; // Out-of-bounds write for arrays that are too small.
 *  }
 * }
 *
 * void print_array_sum(int* array) {
 *  int sum = 0;
 *  for(int i = 0; i<= 10; i++) {
 *      sum += array[i]; // Out-of-bounds read for arrays that are too small.
 *  }
 *  printf("%d\n", sum);
 * }
 *
 * int main() {
 *  int* array = calloc(5, sizeof(int));
 *  set_array_elements(array);
 *  free(array);
 *
 *  array = malloc(5 * sizeof(int));
 *  print_array_sum(array);
 *
 *  puts((void*) array - 1); // Parameter is an out-of-bounds pointer.
 *  free(array);
 * }
 */

@SuppressWarnings("TypeName")
public class CWE119_125_787_Test extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_119_125_787_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Map<CWEReport, CWEReport> cweReportMap = Logging.getCWEReports();

        Address address = GlobalState.flatAPI.toAddr(0x104fc);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x104c4)))
                .get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x1055c);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x10528))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE125, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x105f4);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x105a0))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE119, "", "").setContext(context).setAddress(address);
        Logging.debug(context.toString());
        assert cweReportMap.containsKey(expect);
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_119_125_787_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Map<CWEReport, CWEReport> cweReportMap = Logging.getCWEReports();

        Address address = GlobalState.flatAPI.toAddr(0x100910);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x1008e8)))
                .get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE125, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x1008bc);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x100894))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x100998);
        context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("main").get(0)).get(0);
        expect = new CWEReport(MemoryCorruption.CWE119, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_119_125_787_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Map<CWEReport, CWEReport> cweReportMap = Logging.getCWEReports();

        Address address = GlobalState.flatAPI.toAddr(0x401191);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x401166)))
                .get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x4011d1);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x4011a1))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE125, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x40124f);
        context = Context.getContext(GlobalState.flatAPI.getGlobalFunctions("main").get(0)).get(0);
        expect = new CWEReport(MemoryCorruption.CWE119, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_119_125_787_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Map<CWEReport, CWEReport> cweReportMap = Logging.getCWEReports();

        Address address = GlobalState.flatAPI.toAddr(0x1125b);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x1122d)))
                .get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x1129b);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x1126b))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE125, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x1133a);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x112c7))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE119, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);
    }

}

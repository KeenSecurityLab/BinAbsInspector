import com.bai.checkers.MemoryCorruption;
import com.bai.env.Context;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
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

public class StrippedStaticTest extends IntegrationTestBase {

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_119_125_787_x64_gcc_strip.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        String configPath = this.getClass().getResource("/binaries/X86_64/cwe_119_125_787_x64_gcc_strip.json")
                .getPath();
        GlobalState.config.setExternalMapPath(configPath);
        Utils.registerExternalFunctionsConfig(program, GlobalState.config);
        analyzeFromAddress(program, GlobalState.flatAPI.toAddr(0x40022e));
        Map<CWEReport, CWEReport> cweReportMap = Logging.getCWEReports();

        Address address = GlobalState.flatAPI.toAddr(0x4001c7);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x40019b)))
                .get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE787, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x400206);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x4001d6))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE125, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x400286);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x40022e))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE119, "", "").setContext(context).setAddress(address);
        assert cweReportMap.containsKey(expect);
    }

}

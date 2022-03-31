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
 * #include <stdio.h>
 * #include <stdlib.h>
 * #include <string.h>
 *
 * #define BUFSIZE1 512
 *
 * void bla(){
 *         char *buf1R1;
 *         char *buf2R1;
 *         buf1R1 = (char *) malloc(BUFSIZE1);
 *         buf2R1 = (char *) malloc(BUFSIZE1);
 *         free(buf1R1);
 *         free(buf2R1);
 *         free(buf1R1);
 * }
 *
 * int main(int argc, char **argv) {
 *         char *buf1R1;
 *         char *buf2R1;
 *         buf1R1 = (char *) malloc(BUFSIZE1);
 *         buf2R1 = (char *) malloc(BUFSIZE1);
 *         free(buf1R1);
 *         free(buf2R1);
 *         free(buf1R1);
 *         bla();
 * }
 */

public class CWE415Test extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cwe_415_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);

        Address address = GlobalState.flatAPI.toAddr(0x104c4);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x1047c)))
                .get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE415, "", "").setAddress(address).setContext(context);
        assert Logging.getCWEReports().containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x1046c);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x1042c))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE415, "", "").setAddress(address).setContext(context);
        assert Logging.getCWEReports().containsKey(expect);
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/cwe_415_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);

        Address address = GlobalState.flatAPI.toAddr(0x100854);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x100818)))
                .get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE415, "", "").setAddress(address).setContext(context);
        assert Logging.getCWEReports().containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x100808);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x1007d4))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE415, "", "").setAddress(address).setContext(context);
        assert Logging.getCWEReports().containsKey(expect);
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/cwe_415_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);

        Address address = GlobalState.flatAPI.toAddr(0x10071f);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x1006d5)))
                .get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE415, "", "").setAddress(address).setContext(context);
        assert Logging.getCWEReports().containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x1006cd);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x10068a))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE415, "", "").setAddress(address).setContext(context);
        assert Logging.getCWEReports().containsKey(expect);
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/cwe_415_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);

        Address address = GlobalState.flatAPI.toAddr(0x112ca);
        Context context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x11265)))
                .get(0);
        CWEReport expect = new CWEReport(MemoryCorruption.CWE415, "", "").setAddress(address).setContext(context);
        assert Logging.getCWEReports().containsKey(expect);

        address = GlobalState.flatAPI.toAddr(0x11257);
        context = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x111fd))).get(0);
        expect = new CWEReport(MemoryCorruption.CWE415, "", "").setAddress(address).setContext(context);
        assert Logging.getCWEReports().containsKey(expect);
    }
}
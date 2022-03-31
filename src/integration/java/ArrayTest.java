import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.util.Logging;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Test;

/**
 * #include <stdio.h>
 * #include <stdlib.h>
 *
 * void heap_based_array(){
 *         char* a = malloc(20);
 *         for(int i=0; i<20;i++){
 *                 *(a + i) = 'A';
 *         }
 *         free(a);
 * }
 *
 * void stack_based_array(){
 *         char a[20];
 *         for(int i=0; i<20;i++){
 *                 a[i] = 'A';
 *         }
 * }
 *
 * int main(int argc, char *argv[argc])
 * {
 *         stack_based_array();
 *         heap_based_array();
 *         return 0;
 * }
 */

public class ArrayTest extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/arrays_arm_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Function mainFunction = program.getListing().getGlobalFunctions("main").get(0);
        Context mainContext = Context.getContext(mainFunction).get(0);
        AbsEnv env = mainContext.getValueBefore(program.getAddressFactory().getAddress("0x10510"));
        Logging.debug(env.toString());
    }

    @Test
    public void test_AARCH64LE() throws Exception {
        String path = this.getClass().getResource("/binaries/AARCH64LE/arrays_armv8_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Function mainFunction = program.getListing().getGlobalFunctions("main").get(0);
        Context mainContext = Context.getContext(mainFunction).get(0);
        AbsEnv env = mainContext.getValueBefore(program.getAddressFactory().getAddress("0x100874"));
        Logging.debug(env.toString());
    }

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/arrays_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Function mainFunction = program.getListing().getGlobalFunctions("main").get(0);
        Context mainContext = Context.getContext(mainFunction).get(0);
        AbsEnv env = mainContext.getValueBefore(program.getAddressFactory().getAddress("0x10071f"));
        Logging.debug(env.toString());
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/arrays_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Function mainFunction = program.getListing().getGlobalFunctions("main").get(0);
        Context mainContext = Context.getContext(mainFunction).get(0);
        AbsEnv env = mainContext.getValueBefore(program.getAddressFactory().getAddress("0x112a3"));
        Logging.debug(env.toString());
    }
}
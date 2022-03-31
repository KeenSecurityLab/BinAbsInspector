import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Heap;
import com.bai.env.region.Reg;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Assert;
import org.junit.Test;

/**
 * #include <map>
 * #include <stdio.h>
 *
 * using namespace std;
 *
 * int main() {
 *     map<int, char *> dataMap;
 *     char * data = (char *)malloc(100);
 *     dataMap[0] = data;
 *     dataMap[1] = data;
 *     dataMap[2] = data;
 *     printf("%s", dataMap[0]);
 * }
 */

public class CppMapTest extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cpp_map_arm_g++.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        for (Context ctx : Context.getPool().keySet()) {
            Logging.debug(ctx.toString());
        }
        Function mainFunction = program.getListing().getGlobalFunctions("main").get(0);
        Context mainContext = Context.getContext(mainFunction).get(0);
        AbsEnv absEnv = mainContext.getValueBefore(GlobalState.flatAPI.toAddr(0x10904));
        KSet r0KSet = absEnv.get(Reg.getALoc("r1"));
        assert r0KSet.iterator().next().getRegion().isHeap();
        Heap heap = (Heap) r0KSet.iterator().next().getRegion();
        Assert.assertEquals(heap.getAllocAddress().getOffset(), 0x10854);
    }
}

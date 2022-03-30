import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Reg;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Assert;
import org.junit.Test;

/**
 * #include <list>
 * #include <stdio.h>
 *
 * using namespace std;
 *
 * int main() {
 *     list<int> dataList;
 *     dataList.push_back(1);
 *     dataList.push_back(2);
 *     dataList.push_back(3);
 *     printf("%d", dataList.back());
 * }
 */

public class CppListTest extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cpp_list_arm_g++.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Function mainFunction = program.getListing().getGlobalFunctions("main").get(0);
        Context mainContext = Context.getContext(mainFunction).get(0);
        AbsEnv absEnv = mainContext.getValueBefore(GlobalState.flatAPI.toAddr(0x10730));
        KSet r0KSet = absEnv.get(Reg.getALoc("r1"));
        Logging.debug(r0KSet.toString());
        KSet expect = new KSet(32)
                .insert(new AbsVal(3));
        Assert.assertEquals(expect, r0KSet);
    }
}

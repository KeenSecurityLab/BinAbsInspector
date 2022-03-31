import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Reg;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Assert;
import org.junit.Test;

/**
 * #include <vector>
 * #include <stdio.h>
 *
 * using namespace std;
 *
 * int main() {
 *     vector<int> dataVector;
 *     dataVector.insert(dataVector.end(), 1, 1);
 *     dataVector.insert(dataVector.end(), 1, 2);
 *     dataVector.insert(dataVector.end(), 1, 3);
 *     printf("%d", dataVector[0]);
 *     printf("%d", dataVector[3]);
 * }
 */

public class CppVectorTest extends IntegrationTestBase {

    @Test
    public void test_ARM32LE() throws Exception {
        String path = this.getClass().getResource("/binaries/ARM32LE/cpp_vector_arm_g++.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);
        Function mainFunction = program.getListing().getGlobalFunctions("main").get(0);
        Context mainContext = Context.getContext(mainFunction).get(0);
        AbsEnv absEnv = mainContext.getValueBefore(GlobalState.flatAPI.toAddr(0x10864));
        KSet r0KSet = absEnv.get(Reg.getALoc("r1"));
        KSet expect = new KSet(32)
                .insert(new AbsVal(1))
                .insert(new AbsVal(2))
                .insert(new AbsVal(3));
        Assert.assertEquals(expect, r0KSet);

        absEnv = mainContext.getValueBefore(GlobalState.flatAPI.toAddr(0X10888));
        r0KSet = absEnv.get(Reg.getALoc("r1"));
        Assert.assertEquals(expect, r0KSet);
    }
}

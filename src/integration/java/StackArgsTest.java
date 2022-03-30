import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.region.Reg;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Program;
import java.io.File;
import org.junit.Test;

public class StackArgsTest extends IntegrationTestBase {

    @Test
    public void test_X86_64() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_64/stack_args_x64_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);

        Context ctx = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x10064e)))
                .get(0);
        AbsEnv absEnv = ctx.getValueBefore(GlobalState.flatAPI.toAddr(0x10068d));
        KSet expect = new KSet(64).insert(new AbsVal(36));
        assert absEnv.get(Reg.getALoc("RAX")).equals(expect);

        ctx = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x10068e))).get(0);
        absEnv = ctx.getValueBefore(GlobalState.flatAPI.toAddr(0x10069c));
        expect = new KSet(64).insert(new AbsVal(1004));
        assert absEnv.get(Reg.getALoc("RAX")).equals(expect);
    }

    @Test
    public void test_X86_32() throws Exception {
        String path = this.getClass().getResource("/binaries/X86_32/stack_args_x32_gcc.out").getPath();
        File file = new File(path);
        Program program = prepareProgram(file);
        analyzeFromMain(program);

        Context ctx = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x10542))).get(0);
        ;
        AbsEnv absEnv = ctx.getValueBefore(GlobalState.flatAPI.toAddr(0x10576));
        KSet expect = new KSet(32).insert(new AbsVal((36)));
        assert absEnv.get(Reg.getALoc("EAX")).equals(expect);

        ctx = Context.getContext(GlobalState.flatAPI.getFunctionAt(GlobalState.flatAPI.toAddr(0x10577))).get(0);
        absEnv = ctx.getValueBefore(GlobalState.flatAPI.toAddr(0x1058e));
        expect = new KSet(32).insert(new AbsVal(1004));
        assert absEnv.get(Reg.getALoc("EAX")).equals(expect);
    }

}

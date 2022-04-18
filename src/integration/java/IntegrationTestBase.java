import com.bai.env.funcs.FunctionModelManager;
import com.bai.util.Utils;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitorAdapter;
import com.bai.env.Context;
import com.bai.solver.InterSolver;
import com.bai.util.Architecture;
import com.bai.util.Config;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import java.io.File;
import java.util.ArrayList;
import java.util.List;
import org.junit.BeforeClass;

public abstract class IntegrationTestBase extends AbstractGhidraHeadlessIntegrationTest {

    @BeforeClass
    public static void initEnv() {
        GlobalState.config = new Config();
        GlobalState.config.setDebug(false);
        Logging.init();
        FunctionModelManager.initAll();
    }

    protected Program prepareProgram(File file) throws Exception {
        GlobalState.reset();
        Program program = AutoImporter.importByUsingBestGuess(file, null, this, new MessageLog(),
                TaskMonitorAdapter.DUMMY);
        AutoAnalysisManager analysisManager = AutoAnalysisManager.getAnalysisManager(program);
        analysisManager.initializeOptions();
        final int tid = program.startTransaction("analysis");
        GlobalState.currentProgram = program;
        GlobalState.flatAPI = new FlatProgramAPI(program);
        if (!program.getOptions(Program.PROGRAM_INFO).getBoolean(Program.ANALYZED, false)) {
            GlobalState.flatAPI.analyzeAll(program);
        }
        program.endTransaction(tid, true);
        GlobalState.arch = new Architecture(program);
        GlobalState.eEntryFunction = Utils.getEntryFunction();
        return program;
    }

    protected void analyzeFromMain(Program program) {
        List<Function> functions = program.getListing().getGlobalFunctions("main");
        assert functions.size() == 1 : "Multiple functions with the name \"main\"";
        Function mainFunction = functions.get(0);
        InterSolver solver = new InterSolver(mainFunction, true);
        solver.run();
    }

    protected void analyzeFromAddress(Program program, Address address) {
        Function startFunction = GlobalState.flatAPI.getFunctionAt(address);
        InterSolver solver = new InterSolver(startFunction, false);
        solver.run();
    }

    protected List<Context> getAllContexts() {
        return new ArrayList<>(Context.getPool().keySet());
    }

}

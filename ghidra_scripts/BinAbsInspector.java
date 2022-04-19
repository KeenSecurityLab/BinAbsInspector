//
//@author Tencent KeenLab
//@category Analysis
//@keybinding
//@menupath Analysis.BinAbsInspector
//@toolbar keenlogo.gif

import com.bai.checkers.CheckerManager;
import com.bai.env.funcs.FunctionModelManager;
import com.bai.util.Config.HeadlessParser;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.listing.Program;
import com.bai.util.CWEReport;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import com.bai.solver.InterSolver;
import com.bai.util.Architecture;
import com.bai.util.Config;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import java.awt.Color;
import java.util.List;
import org.apache.commons.lang3.StringUtils;

public class BinAbsInspector extends GhidraScript {

    protected boolean prepareProgram() {
        GlobalState.currentProgram = this.currentProgram;
        GlobalState.flatAPI = this;
        Language language = GlobalState.currentProgram.getLanguage();
        return language != null;
    }

    protected boolean analyzeFromMain() {
        List<Function> functions = GlobalState.currentProgram.getListing().getGlobalFunctions("main");
        if (functions == null || functions.size() == 0) {
            return false;
        }
        Function entryFunction = functions.get(0);
        if (entryFunction == null) {
            Logging.error("Cannot find entry function");
            return false;
        }
        Logging.info("Running solver on \"" + entryFunction + "()\" function");
        InterSolver solver = new InterSolver(entryFunction, true);
        solver.run();
        return true;
    }

    protected boolean analyzeFromAddress(Address entryAddress) {
        Function entryFunction = GlobalState.flatAPI.getFunctionAt(entryAddress);
        if (entryAddress == null) {
            Logging.error("Could not find entry function at " + entryAddress);
            return false;
        }
        Logging.info("Running solver on \"" + entryFunction + "()\" function");
        InterSolver solver = new InterSolver(entryFunction, false);
        solver.run();
        return true;
    }

    /**
     * Start analysis with following steps:
     * 1. Start from specific address if user provided, the address must be the entrypoint of a function.
     * 2. Start from "main" function if step 1 fails.
     * 3. Start from "e_entry" address from ELF header if step 2 fails.
     * @return
     */
    protected boolean analyze() {
        Program program = GlobalState.currentProgram;
        if (program == null) {
            Logging.error("Import program error.");
            return false;
        }
        String entryAddressStr = GlobalState.config.getEntryAddress();
        if (entryAddressStr != null) {
            Address entryAddress = GlobalState.flatAPI.toAddr(entryAddressStr);
            return analyzeFromAddress(entryAddress);
        } else {
            GlobalState.eEntryFunction = Utils.getEntryFunction();
            if (GlobalState.eEntryFunction == null) {
                Logging.error("Cannot find entry function, maybe unsupported file format or corrupted header.");
                return false;
            }
            if (!analyzeFromMain()) {
                Logging.info("Start from entrypoint");
                Logging.info("Running solver on \"" + GlobalState.eEntryFunction + "()\" function");
                InterSolver solver = new InterSolver(GlobalState.eEntryFunction, false);
                solver.run();
                return true;
            }
        }
        return true;
    }

    private void guiProcessResult() {
        if (!GlobalState.config.isGUI()) {
            return;
        }
        String msg = "Analysis finish!\n Found " + Logging.getCWEReports().size() + " CWE Warning.";
        GlobalState.ghidraScript.popup(msg);
        Logging.info(msg);
        for (CWEReport report : Logging.getCWEReports().keySet()) {
            GlobalState.ghidraScript.setBackgroundColor(report.getAddress(), Color.RED);
            GlobalState.ghidraScript.setEOLComment(report.getAddress(), report.toString());
            Logging.warn(report.toString());
        }
    }

    @Override
    public void run() throws Exception {
        GlobalState.config = new Config();
        if (isRunningHeadless()) {
            String allArgString = StringUtils.join(getScriptArgs()).strip();
            GlobalState.config = HeadlessParser.parseConfig(allArgString);
        } else {
            GlobalState.ghidraScript = this;
            GlobalState.config = new Config();
            GlobalState.config.setGUI(true);
            ConfigDialog dialog = new ConfigDialog(GlobalState.config);
            dialog.showDialog();
            if (!dialog.isSuccess()) {
                return;
            }
        }
        if (!Logging.init()) {
            return;
        }
        FunctionModelManager.initAll();
        if (GlobalState.config.isEnableZ3() && !Utils.checkZ3Installation()) {
            return;
        }
        Logging.info("Preparing the program");
        if (!prepareProgram()) {
            Logging.error("Failed to prepare the program");
            return;
        }
        if (isRunningHeadless()) {
            if (!Utils.registerExternalFunctionsConfig(GlobalState.currentProgram, GlobalState.config)) {
                return;
            }
        } else {
            Utils.loadCustomExternalFunctionFromLabelHistory(GlobalState.currentProgram);
        }
        GlobalState.arch = new Architecture(GlobalState.currentProgram);
        boolean success = analyze();
        if (!success) {
            Logging.error("Failed to analyze the program: no entrypoint.");
            return;
        }
        Logging.info("Running checkers");
        CheckerManager.runCheckers(GlobalState.config);
        guiProcessResult();
        GlobalState.reset();
    }
}

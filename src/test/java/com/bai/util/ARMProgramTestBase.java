package com.bai.util;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import org.junit.Before;
import org.junit.BeforeClass;

public abstract class ARMProgramTestBase extends AbstractGhidraHeadlessIntegrationTest {

    protected Program program;
    protected ProgramBuilder programBuilder;

    @BeforeClass
    public static void initClass() {
        GlobalState.config = new Config();
        Logging.init();
    }

    @Before
    public void init() throws Exception {
        programBuilder = new ProgramBuilder("Test", ProgramBuilder._ARM);
        program = programBuilder.getProgram();
        int txId = program.startTransaction("Add memory");
        programBuilder.createMemory(".text", "0x1000", 0x100).setExecute(true);
        program.endTransaction(txId, true);
        programBuilder.analyze();
        GlobalState.currentProgram = program;
        GlobalState.flatAPI = new FlatProgramAPI(program);
        GlobalState.reset();
        GlobalState.arch = new Architecture(program);
    }
}

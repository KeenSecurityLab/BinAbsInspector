package com.bai.solver;

import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;

public class InterSolver {

    private Function entry;
    private boolean isMain;

    public InterSolver(Function entry, boolean isMain) {
        this.entry = entry;
        this.isMain = isMain;
    }

    public void run() {
        Context mainContext = Context.getEntryContext(entry);
        mainContext.initContext(new AbsEnv(), isMain);
        int timeout = GlobalState.config.getTimeout();
        if (timeout < 0) {
            Context.mainLoop(mainContext);
        } else {
            Context.mainLoopTimeout(mainContext, timeout);
        }
    }

}
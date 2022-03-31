package com.bai.solver;

import com.bai.env.AbsEnv;
import com.bai.env.Context;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;

/**
 * The class for interprocedural analysis.
 */
public class InterSolver {

    private Function entry;
    private boolean isMain;

    /**
     * Constructor for InterSolver
     * @param entry The start point function for interprocedural analysis
     * @param isMain The flag to indicate whether the entry is conventional "main" function
     */
    public InterSolver(Function entry, boolean isMain) {
        this.entry = entry;
        this.isMain = isMain;
    }


    /**
     * The driver function for the interprocedural analysis  
     */
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
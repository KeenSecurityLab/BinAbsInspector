package com.bai.solver;

import ghidra.program.model.listing.Function;
import ghidra.util.task.TaskMonitor;

import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.Map;
import java.util.Set;

/** Call graph */
public class CallGraph extends GraphBase<Function> {

    private Function entryFunction;
    
    private static Map<Function, CallGraph> pool = new HashMap<>();

    /**
     * @hidden
     * Reset the CallGraph pool
     */
    public static void resetPool() {
        pool.clear();
    }

    /**
     * Returns the CallGraph for the given function. If the CallGraph does not exist, a new one will
     * be created.
     * @param f The function to get the CallGraph for.
     * @return The CallGraph for the given function f.
     */
    public static CallGraph getCallGraph(Function f) {
        if (pool.containsKey(f)) {
            return pool.get(f);
        }
        CallGraph callGraph = new CallGraph(f);
        pool.put(f, callGraph);
        return callGraph;
    }


    /**
     * Initialize a CallGraph of the given entry function.
     * @param entryFunction The entry function to create a CallGraph.
     */
    private CallGraph(Function entryFunction) {
        this.entryFunction = entryFunction;
        LinkedList<Function> workList = new LinkedList<>();
        Set<Function> visited = new HashSet<>();
        workList.add(entryFunction);
        visited.add(entryFunction);
        while (!workList.isEmpty()) {
            Function front = workList.remove();
            Set<Function> succs = front.getCalledFunctions(TaskMonitor.DUMMY);
            for (Function succ : succs) {
                addEdge(front, succ);
                if (visited.contains(succ)) {
                    continue;
                }
                visited.add(succ);
                workList.add(succ);
            }
        }
    }

    /**
     * @hidden
     */
    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }

    /**
     * @hidden
     */
    @Override
    public int hashCode() {
        return entryFunction.hashCode();
    }
}

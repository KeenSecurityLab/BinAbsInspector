package com.bai.solver;

import com.bai.util.GlobalState;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.FlowType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Stack;

/**
 * The control flow graph of a function.
 */
public class CFG extends GraphBase<Address> {
    
    private Function f;
 
    private static Map<Function, CFG> pool = new HashMap<>();

    private final Map<Address, Integer> wtoMap = new HashMap<>();
    
    private Set<Integer> isInLoopSet = new HashSet<>();

    private int order;

    /**
     * Initialize a CFG of the given function f.
     */
    private CFG(Function f) {
        this.f = f;
        Address entry = f.getEntryPoint();
        LinkedList<Address> worklist = new LinkedList<>();
        worklist.add(entry);
        Set<Address> visited = new HashSet<>();
        while (!worklist.isEmpty()) {
            Address cur = worklist.remove();
            visited.add(cur);
            Address[] succ = getFlowTargets(cur);
            if (succ.length != 0) {
                for (Address elem : succ) { // adds edges for all flow targets
                    addEdge(cur, elem);
                    if (!visited.contains(elem) && !worklist.contains(elem)) { // add to worklist if not visited
                        worklist.add(elem);
                    }
                }
            } else {
                getNode(cur);
            }
        }
        if (sum > 0) {
            computeWTO();
        }
    }

    /**
     * Compute Weak Topological Ordering.
     */
    private void computeWTO() {
        order = sum;
        depthFirstNums = new int[sum];
        Stack<Integer> stack = new Stack<>();
        isInLoopSet.clear();
        num = 0;
        visit(0, stack);
    }

    private int visit(int id, Stack<Integer> stack) {
        stack.push(id);
        num++;
        depthFirstNums[id] = num;    // label this node with the depth first numbering
        int head = depthFirstNums[id];
        boolean loop = false;
        int[] succs = getSuccs(id);
        for (int e : succs) {
            int min;
            if (depthFirstNums[e] == 0) {    // not yet explored?
                min = visit(e, stack);
            } else {
                min = depthFirstNums[e];
            }
            if (min != -1 && min <= head) {
                head = min;
                loop = true;
            }
        }

        if (head == depthFirstNums[id]) {
            depthFirstNums[id] = -1; // +Infinite, unreachable
            int elem = stack.pop();
            if (loop) {
                isInLoopSet.add(elem);

                while (elem != id) {
                    depthFirstNums[elem] = 0;
                    elem = stack.pop();
                    isInLoopSet.add(elem);
                }
                component(id, stack);
            }
            wtoMap.put(idToNodeMap.get(id), order);
            order--;
            assert (order >= 0);
        }
        return head;
    }

    private void component(int id, Stack<Integer> stack) {
        int[] succs = getSuccs(id);
        for (int e : succs) {
            if (depthFirstNums[e] != -1) {
                visit(e, stack);
            }
        }
    }

    /**
     * Return the targets of this instruction's flow.
     */
    private static Address[] getFlowTargets(Address cur) {
        Instruction inst = GlobalState.flatAPI.getInstructionAt(cur);
        if (inst == null) {
            return new Address[0];
        }

        ArrayList<Address> flowTargets = new ArrayList<>();
        FlowType flowType = inst.getFlowType();

        if (flowType.isConditional()) {
            flowTargets.add(inst.getFallThrough());
        }

        if (flowType.isTerminal()) {
            return flowTargets.toArray(Address[]::new);
        }

        if (flowType.isJump()) {
            Address[] flows = inst.getFlows();
            if (flowType.isComputed()) {
                flowTargets.addAll(Arrays.asList(flows));
            }
            if (flows.length == 0) {
                return flowTargets.toArray(Address[]::new);
            }
            if (flowType.isConditional()) {
                flowTargets.add(flows[0]);
            } else if (flowType.isUnConditional()) {
                flowTargets.add(flows[0]);
            } else {
                flowTargets.addAll(Arrays.asList(flows));
            }
        } else if (flowType.isFallthrough()) {
            Address address = inst.getFallThrough();
            if (GlobalState.flatAPI.getInstructionAt(address) != null) {
                flowTargets.add(address);
            }
        } else {
            // weird cases, probably has fall through
            Address address = inst.getFallThrough();
            if (GlobalState.flatAPI.getInstructionAt(address) != null) {
                flowTargets.add(address);
            }

        }
        return flowTargets.toArray(Address[]::new);
    }

    /**
     * Re-compute the Weak Topological Ordering (WTO) if the graph has changed.
     */
    protected void refresh() {
        if (!changed) {
            return;
        }
        computeWTO();
        changed = false;
    }

    /**
     * Get WTO (Weak Topological Ordering) for each address in this CFG
     * @return The WTO map for each address of this CFG
     */ 
    public Map<Address, Integer> getWTOMap() {
        return wtoMap;
    }

    /**
     * Return the CFG for the given function. If the CFG does not exist, a new one is
     * created and returned.
     * @param f The function to get the CFG for.
     * @return The CFG for the given function f.
     */
    public static CFG getCFG(Function f) {
        CFG cfg = pool.get(f);
        if (cfg != null) {
            return cfg;
        }
        // make a new CFG for the function f if the CFG does not exist
        cfg = new CFG(f);
        pool.put(f, cfg);
        return cfg;
    }

    /**
     * @hidden
     */ 
    public static void resetPool() {
        pool.clear();
    }

    /**
     * Check if the given node is in a loop
     * @param node The function that will be checked
     * @return True if the given node ia a loop
     */
    public boolean isInLoop(Address node) {
        return isInLoopSet.contains(nodeToIdMap.get(node));
    }

    /**
     * @hidden
     */ 
    public int getSum() {
        return sum;
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
        return f.hashCode();
    }

}

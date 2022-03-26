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


public class CFG extends GraphBase<Address> {

    private Function f;
    /**
     * A map of all CFG mapping to its function
     */
    static Map<Function, CFG> pool = new HashMap<>();

    private final Map<Address, Integer> wtoMap = new HashMap<>();

    /**
     * Set of node in the loop
     */
    private Set<Integer> isInLoopSet = new HashSet<>();


    private final List<Integer> wideningPointList = new ArrayList<>();

    public Map<Address, Integer> getWTOMap() {
        return wtoMap;
    }

    private int order;

    /**
     * Returns the CFG for the given function. If the CFG does not exist, a new one is
     * created and returned.
     *
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
     * Reset the CFG pool
     */
    public static void resetPool() {
        pool.clear();
    }

    /**
     * Initialize a CFG of the given function f.
     *
     * @param f The function to create a CFG for.
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
     * Return if the given node is in a loop
     *
     * @param node The function that will be checked
     * @return True if the given node ia a loop
     */
    public boolean isInLoop(Address node) {
        return isInLoopSet.contains(nodeToIdMap.get(node));
    }

    public int getSum() {
        return sum;
    }

    /**
     * Compute Weak Topological Ordering.
     */
    public void computeWTO() {
        order = sum;
        depthFirstNums = new int[sum];
        Stack<Integer> stack = new Stack<>();
        isInLoopSet.clear();
        num = 0;
        visit(0, stack);
    }

    /**
     * Re-compute the Weak Topological Ordering if the graph has changed.
     */
    public void refresh() {
        if (!changed) {
            return;
        }
        computeWTO();
        changed = false;
    }

    /**
     * Performs a depth-first search as well as creating a Weak Topological Ordering
     * at the given id's nodes.
     *
     * @param id The id of the CFG node to start the visiting process.
     * @param stack to record the id
     * @return
     */
    private int visit(int id, Stack<Integer> stack) {
        stack.push(id);
        num++;
        depthFirstNums[id] = num;    // labels this node with the depth first numbering
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

    /**
     * @param id
     * @param stack
     */
    private void component(int id, Stack<Integer> stack) {
        wideningPointList.add(id);
        int[] succs = getSuccs(id);
        for (int e : succs) {
            if (depthFirstNums[e] != -1) {
                visit(e, stack);
            }
        }
    }

    /**
     * Checks if the given address is a widening point.
     * This method also creates a CFGNode for the given address if needed.
     *
     * @param address The address of the address to check if it is a widening point or not
     * @return true if it is a widening point, false otherwise
     */
    public boolean isWideningPoint(Address address) {
        Node tmp = getNode(address);
        int id = -1;
        for (Map.Entry<Integer, Address> elem : idToNodeMap.entrySet()) {
            if (elem.getValue().equals(address)) {
                id = elem.getKey();
                break;
            }
        }
        if (id == -1) {    // address has not been created, cannot be WP
            return false;
        }
        return wideningPointList.contains(id);
    }

    /**
     * Returns the targets of this instruction's flow.
     *
     * @param cur The current address.
     * @return An array of addresses representing the target of the flow.
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


    @Override
    public boolean equals(Object obj) {
        return super.equals(obj);
    }

    @Override
    public int hashCode() {
        return f.hashCode();
    }


}

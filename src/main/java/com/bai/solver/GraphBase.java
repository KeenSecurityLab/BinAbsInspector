package com.bai.solver;


import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public abstract class GraphBase<T> {


    /**
     * Whether the graph is changed
     */
    protected boolean changed = false;

    /**
     * Map node's value to Node
     */
    private final Map<T, Node> nodeMap = new HashMap<>();


    /**
     * Map id to to node
     */
    protected final Map<Integer, T> idToNodeMap = new HashMap<>();

    /**
     * Map node to id
     */
    protected final Map<T, Integer> nodeToIdMap = new HashMap<>();


    /**
     * used for depth first numbering
     */
    protected int num = 0;


    protected int sum = 0;

    /**
     * An array of integers, where the indexes represent the id of each node and
     * the values are the depth-first numbering.
     */
    protected int[] depthFirstNums = null;

    protected class Node {

        private T value;

        /**
         * The pred of this node
         */
        private Set<T> in = new HashSet<>();

        /**
         * The succ of this node
         */
        private Set<T> out = new HashSet<>();

        /**
         * Create a node from the given parameter
         */
        public Node(T value) {
            this.value = value;
        }

        @Override
        public int hashCode() {
            return value != null ? value.hashCode() : 0;
        }
    }

    /**
     * Get a Node for the given value from the graph.
     * This may create a new node if needed.
     * @param value The node's value
     * @return the graph node.
     */
    public Node getNode(T value) {
        if (nodeMap.containsKey(value)) {
            return nodeMap.get(value);
        }
        Node res = new Node(value);
        nodeMap.put(value, res);
        idToNodeMap.put(sum, value);
        nodeToIdMap.put(value, sum);
        sum++;
        changed = true;
        return res;
    }


    /**
     * Create a graph edge with source and destination.
     * This also creates the graph node of the given parameters if needed.
     * @param from the source node's value
     * @param to the destination node's value
     */
    public void addEdge(T from, T to) {
        Node src = getNode(from);
        Node dst = getNode(to);
        if (src.out.contains(to)) {
            changed = false;
            return;
        }
        src.out.add(to);
        dst.in.add(from);
        changed = true;
    }

    /**
     * Delete a graph edge with source and destination.
     * @param from the source node's value
     * @param to the destination node's value
     */
    public void deleteEdge(T from, T to) {
        Node src = getNode(from);
        Node dst = getNode(to);

        if (src.out.remove(to)) {
            changed = true;
        }
        if (dst.in.remove(from)) {
            changed = true;
        }
        if (src.out.isEmpty() && src.in.isEmpty()) {
            idToNodeMap.remove(nodeToIdMap.get(src));
            nodeToIdMap.remove(src);
            nodeMap.remove(src);
        }
        if (dst.out.isEmpty() && dst.in.isEmpty()) {
            idToNodeMap.remove(nodeToIdMap.get(dst));
            nodeToIdMap.remove(dst);
            nodeMap.remove(dst);
        }
    }

    /**
     * @hidden
     * @deprecated Weird method, to be removed
     * Reset predecessor relationship of a node
     * @param node The node to be processed
     */
    public void resetPreds(T node) {
        for (T t : getPreds(node)) {
            deleteEdge(t, node);
        }
    }

    /**
     * @hidden
     * @deprecated Weird method, to be removed
     * Reset successor relationship of a node
     * @param node The node to be processed
     */
    public void resetSuccs(T node) {
        for (T t : getSuccs(node)) {
            deleteEdge(node, t);
        }
    }

    /**
     * Return a list of the node's successors
     * @param value the node value
     * @return Return a list of the node's successors
     */
    public List<T> getSuccs(T value) {
        Node tmp = getNode(value);
        return new LinkedList<>(tmp.out);
    }

    /**
     * Return an array of the node's successors
     * @param id the node's id
     * @return Return an array of the node's successors
     */
    protected int[] getSuccs(int id) {
        Node tmp = nodeMap.get(idToNodeMap.get(id));
        int[] res = new int[tmp.out.size()];
        if (tmp.out.size() == 0) {
            return res;
        }
        int i = 0;
        for (T t : tmp.out) {
            res[i++] = nodeToIdMap.get(t);
        }
        return res;
    }

    /**
     * Return a list of the node's predecessors
     * @param value the node value
     * @return Return a list of the node's predecessors
     */
    public List<T> getPreds(T value) {
        Node tmp = getNode(value);
        return new LinkedList<>(tmp.in);
    }

    /**
     * Return an array of the node's predecessors
     * @param id the node's id
     * @return Return an array of the node's predecessors
     */
    protected int[] getPreds(int id) {
        Node tmp = nodeMap.get(idToNodeMap.get(id));
        int[] res = new int[tmp.in.size()];
        if (tmp.in.size() == 0) {
            return res;
        }
        int i = 0;
        for (T t : tmp.in) {
            res[i++] = nodeToIdMap.get(t);
        }
        return res;
    }

    /**
     * Check if the graph has a path from src to dst
     * @param from The src node
     * @param to The dst node
     * @return True if it has a path from src to dst
     */
    public boolean hasPath(T from, T to) {
        int src = nodeToIdMap.get(from) == null ? -1 : nodeToIdMap.get(from);
        int dst = nodeToIdMap.get(to) == null ? -1 : nodeToIdMap.get(to);
        if (src == -1 || dst == -1) {
            return false;
        }
        LinkedList<Integer> workList = new LinkedList<>();
        Set<Integer> visited = new HashSet<>();
        workList.add(src);
        visited.add(src);
        while (!workList.isEmpty()) {
            int now = workList.remove();
            for (Integer succ : getSuccs(now)) {
                if (succ == dst) {
                    return true;
                }
                if (visited.contains(succ)) {
                    continue;
                }
                visited.add(succ);
                workList.add(succ);
            }
        }
        return false;
    }
    
}

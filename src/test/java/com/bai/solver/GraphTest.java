package com.bai.solver;

import static org.junit.Assert.assertEquals;

import ghidra.program.model.listing.Function;
import java.util.ArrayList;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

public class GraphTest  {

    static final int DEFAULT_TEST_SIZE = 100;

    public void floyd(boolean[][] g) {
        for (int k = 0; k < DEFAULT_TEST_SIZE; k++) {
            for (int i = 0; i < DEFAULT_TEST_SIZE; i++) {
                for (int j = 0; j < DEFAULT_TEST_SIZE; j++) {
                    if (g[i][k] && g[k][j]) {
                        g[i][j] = true;
                    }
                }
            }
        }
    }

    CallGraph callGraph = null;
    CFG cfg = null;

    @Before
    public void setUp() throws Exception {
        callGraph = CallGraph.getCallGraph(Mockito.mock(Function.class));

    }


    @Test
    public void testAddEdge() {
        Function src = Mockito.mock(Function.class);
        Function dst = Mockito.mock(Function.class);
        callGraph.addEdge(src, dst);
        System.out.print("from " + src);
        System.out.println(" to " + dst);

        Function expSrc = callGraph.getPreds(dst).get(0);
        Function expDst = callGraph.getSuccs(src).get(0);

        assertEquals(expSrc, src);
        assertEquals(expDst, dst);
    }

    @Test
    public void testResetSuccs() {
        Function f1 = Mockito.mock(Function.class);
        Function f2 = Mockito.mock(Function.class);
        Function f3 = Mockito.mock(Function.class);
        callGraph.addEdge(f1, f2);
        callGraph.addEdge(f1, f3);

        callGraph.resetSuccs(f1);
        assertEquals(0, callGraph.getSuccs(f1).size());
    }



    @Test
    public void testResetPreds() {
        Function f1 = Mockito.mock(Function.class);
        Function f2 = Mockito.mock(Function.class);
        Function f3 = Mockito.mock(Function.class);
        callGraph.addEdge(f2, f1);
        callGraph.addEdge(f3, f1);
        callGraph.resetPreds(f1);
        assertEquals(0, callGraph.getSuccs(f1).size());
    }


    @Test
    public void testHasPath() {
        Function f1 = Mockito.mock(Function.class);
        Function f2 = Mockito.mock(Function.class);
        Function f3 = Mockito.mock(Function.class);
        Function f4 = Mockito.mock(Function.class);
        callGraph.addEdge(f1, f2);
        callGraph.addEdge(f2, f3);
        callGraph.addEdge(f3, f4);
        System.out.println(callGraph.hasPath(f4, f1));

    }


    @Test
    public void testFinal() {

        boolean[][] g = new boolean[DEFAULT_TEST_SIZE][DEFAULT_TEST_SIZE];// comparison graph
        ArrayList<Function> functions = new ArrayList<>();
        for (int i = 0; i < DEFAULT_TEST_SIZE; i++) {
            functions.add(Mockito.mock(Function.class));
        }
        //init a complete graph
        for (int i = 0; i < DEFAULT_TEST_SIZE; i++) {
            for (int j = 0; j < DEFAULT_TEST_SIZE; j++) {
                callGraph.addEdge(functions.get(i), functions.get(j));
                g[i][j] = true;
            }
        }

        // random operation
        for (int i = 0; i < 50; i++) {
            int rand = (int) (Math.random() * 10);
            rand = rand % 2;//opt
            int k = (int) (Math.random() * 100);
            k = k % DEFAULT_TEST_SIZE;//node
            if (rand == 1) {
                //reset succs of node k
                callGraph.resetSuccs(functions.get(k));
                for (int j = 0; j < DEFAULT_TEST_SIZE; j++) {
                    g[k][j] = false;
                }
            } else {
                //reset preds of node k
                callGraph.resetPreds(functions.get(k));
                for (int j = 0; j < DEFAULT_TEST_SIZE; j++) {
                    g[j][k] = false;
                }
            }
        }
        //random add and sub edges
        for (int i = 1; i <= 100; i++) {
            int u = (int) (Math.random() * 100);
            int v = (int) (Math.random() * 100);
            u %= DEFAULT_TEST_SIZE;
            v %= DEFAULT_TEST_SIZE;
            int opt = (int) (Math.random() * 100);
            opt %= 2;//opt 1 stand for addCallEdge and 2 stand for deleteCallEdge
            if (opt == 1) {
                callGraph.addEdge(functions.get(u), functions.get(v));
                g[u][v] = true;
            } else {
                callGraph.deleteEdge(functions.get(u), functions.get(v));
                g[u][v] = false;
            }
        }
        //run the floyd to get the graph reachability(graph g)

        floyd(g);

        //compare the two graph
        for (int i = 0; i < DEFAULT_TEST_SIZE; i++) {
            for (int j = 0; j < DEFAULT_TEST_SIZE; j++) {
                assertEquals(g[i][j], callGraph.hasPath(functions.get(i), functions.get(j)));
                System.out.println(i + " -> " + j + " exp:" + g[i][j] + " act:" + callGraph.hasPath(functions.get(i),
                        functions.get(j)));
            }
        }
    }


}

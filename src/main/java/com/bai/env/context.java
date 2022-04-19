package com.bai.env;

import com.bai.env.funcs.externalfuncs.ExternalFunctionBase;
import com.bai.env.region.Local;
import com.bai.solver.CFG;
import com.bai.solver.PcodeVisitor;
import com.bai.solver.Worklist;
import com.bai.util.Logging;
import com.bai.util.Utils;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import com.bai.util.GlobalState;
import java.util.Stack;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.stream.Collectors;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.javimmutable.collections.JImmutableSet;
import org.javimmutable.collections.tree.JImmutableTreeMap;


/** Context **/
public class context {

    private static final Map<context, context> pool = new HashMap<>();

    private static context current;

    private static Stack<context> active = new Stack<>();

    private static Stack<context> pending = new Stack<>();

    private Function function;

    private long[] callstring = new long[GlobalState.config.getCallStringK()]; // default value is zeroes

    private Function[] funcs = new Function[GlobalState.config.getCallStringK()];

    private final Map<Address, AbsEnv> inValues = new HashMap<>();

    private final Map<Address, AbsEnv> outValues = new HashMap<>();

    private KSet oldSpKSet = new KSet(GlobalState.arch.getDefaultPointerSize() * 8);

    private JImmutableTreeMap<ALoc, KSet> exitValue = JImmutableTreeMap.of();

    private Worklist worklist;

    private context(Function function) {
        this.function = function;
        this.worklist = new Worklist(CFG.getCFG(function));
    }

    private context(Function function, long[] callString) {
        this.function = function;
        this.callstring = callString;
        this.worklist = new Worklist(CFG.getCFG(function));
    }

    /**
     * Get a map with addresses and their "before" abstract environments under this context
     */
    public Map<Address, AbsEnv> getAbsEnvIn() {
        return inValues;
    }

    /**
     * Get a map with addresses and their "after" abstract environments under this context
     */
    public Map<Address, AbsEnv> getAbsEnvOut() {
        return outValues;
    }

    /**
     * Getter for function field in Context
     */
    public Function getFunction() {
        return function;
    }

    /**
     * Getter for call string field in Context
     */
    public long[] getCallString() {
        return callstring;
    }

    /**
     * @hidden
     * @deprecated Not recommended to use. To be removed
     */
    public Function[] getFuncs() {
        return funcs;
    }

    /**
     * @hidden
    */
    public static Map<context, context> getPool() {
        return pool;
    }

    /**
     * Get exit value of this context (i.e., return value)
     */
    public JImmutableTreeMap<ALoc, KSet> getExitValue() {
        return exitValue;
    }

    /**
     * Set exit value of this context, generally for return instructions
     */
    public void setExitValue(JImmutableTreeMap<ALoc, KSet> exitValue) {
        this.exitValue = exitValue;
    }

    /**
     * Set the "before" abstract environment for an address under this context
     */
    public void setValueBefore(Address addr, AbsEnv env) {
        assert (env != null);
        inValues.put(addr, env);
    }

    /**
     * Set the "after" abstract environment for an address under this context
     */
    public void setValueAfter(Address addr, AbsEnv env) {
        assert (env != null);
        outValues.put(addr, env);
    }

    /**
     * Get the abstract environment before an address under this context
     */
    public AbsEnv getValueBefore(Address addr) {
        if (inValues.containsKey(addr)) {
            return inValues.get(addr);
        }
        return new AbsEnv();
    }

    /**
     * Get the abstract environment after an address under this context
     */
    public AbsEnv getValueAfter(Address addr) {
        if (outValues.containsKey(addr)) {
            return outValues.get(addr);
        }
        return null;
    }

    /**
     * @hidden
     */
    public KSet getOldSpKSet() {
        return oldSpKSet;
    }

    private void updateOldSp(KSet kSet) {
        KSet union = oldSpKSet.join(kSet);
        oldSpKSet = (union == null) ? oldSpKSet : union;
        if (oldSpKSet.isTop()) {
            Logging.warn("K is too small to hold old stack frames, please consider increase K value: Context("
                    + this.toString() + ")");
        }
    }

    private void updateSP(AbsEnv inOutEnv) { ALoc spALoc = ALoc.getSPALoc(); KSet oldSpKSet = inOutEnv.get(spALoc); if (oldSpKSet.isNormal()) { JImmutableSet<AbsVal> filteredSet = oldSpKSet.getInnerSet(); for (AbsVal absVal : filteredSet) { if (!absVal.getRegion().isLocal()) { filteredSet = filteredSet.delete(absVal); }
            }
            oldSpKSet = new KSet(filteredSet, oldSpKSet.getBits());
            updateOldSp(oldSpKSet);
        }
        Local local = Local.getLocal(getFunction());
        KSet spKSet = new KSet(GlobalState.arch.getDefaultPointerSize() * 8);
        spKSet = spKSet.insert(AbsVal.getPtr(local));
        inOutEnv.set(spALoc, spKSet, true);
    }

    /**
     * Get partial call string from the original one after poping the latest call site
     */
    public long[] popLast() {
        long[] cs = this.callstring;
        long[] res = new long[GlobalState.config.getCallStringK()];
        System.arraycopy(cs, 0, res, 1, GlobalState.config.getCallStringK() - 1);
        return res;
    }

    /**
     * Taint argc and argv for main function
     */
    public void prepareMainAbsEnv(AbsEnv absEnv, Function mainFunction) {
        final long TAINT_ARGV_COUNT = 5;
        Utils.defineMainFunctionSignature(mainFunction);

        Local entryLocal = Local.getLocal(GlobalState.eEntryFunction);

        oldSpKSet = oldSpKSet.insert(AbsVal.getPtr(entryLocal));
        // Temporarily set sp point to start
        ALoc spALoc = ALoc.getSPALoc();
        final KSet mainSP = absEnv.get(spALoc);
        KSet tmpSP = new KSet(GlobalState.arch.getDefaultPointerSize() * 8).insert(AbsVal.getPtr(entryLocal));
        absEnv.set(spALoc, tmpSP, true);

        // Set argc to TOP
        List<ALoc> argcALocs = ExternalFunctionBase.getParamALocs(mainFunction, 0, absEnv);
        if (argcALocs.size() != 1) {
            Logging.error("Multiple ALoc for argc.");
            return;
        }
        ALoc argcALoc = argcALocs.get(0);
        if (argcALoc.getRegion().isLocal()) {
            argcALoc = ALoc.getALoc(entryLocal, argcALoc.getBegin(), argcALoc.getLen());
        }
        absEnv.set(argcALoc, KSet.getTop(), true);

        // Set argv to TOP with taint
        List<ALoc> argvALocs = ExternalFunctionBase.getParamALocs(mainFunction, 1, absEnv);
        if (argvALocs.size() != 1) {
            Logging.error("Multiple ALoc for argv.");
            return;
        }
        ALoc argvALoc = argvALocs.get(0);
        long offset;
        if (argvALoc.getRegion().isLocal()) {
            argvALoc = ALoc.getALoc(entryLocal, argvALoc.getBegin(), argcALoc.getLen());
            offset = argvALoc.getBegin() + argvALoc.getLen();
        } else {
            offset = entryLocal.getBase();
        }
        long taints = TaintMap.getTaints(this, GlobalState.eEntryFunction);
        int unit = GlobalState.arch.getDefaultPointerSize();
        for (int i = 0; i < TAINT_ARGV_COUNT; i++) {
            absEnv.set(ALoc.getALoc(entryLocal, offset + ((long) i * unit), unit), KSet.getTop(taints), true);
        }

        KSet argvPtrKSet = new KSet(argvALoc.getLen() * 8).insert(AbsVal.getPtr(entryLocal, offset));
        absEnv.set(argvALoc, argvPtrKSet, true);
        // reset sp
        absEnv.set(spALoc, mainSP, true);
    }

    /**
     * Initialize necessary dataflow facts inside a created context
     * @param caller New abstract environment before entrance into this context
     * @param isMain Indicate whether this is a context for conventional "main" functions
     * @return True if the abstract environment before the context entry has been changed, false otherwise 
     */
    public boolean initContext(AbsEnv caller, boolean isMain) {
        Function callee = getFunction();
        Address entry = callee.getEntryPoint();
        AbsEnv env = new AbsEnv(caller);
        updateSP(env);
        if (isMain) {
            prepareMainAbsEnv(env, callee);
        }
        AbsEnv oldInit = getValueBefore(entry);

        AbsEnv res = oldInit.join(env);
        if (res != null) {
            setValueBefore(entry, res);
            insertToWorklist(entry);
            return true;
        }
        return false;
    }

    /**
     * @hidden
     * Insert an address into the worklist of this context
     */
    public void insertToWorklist(Address addr) {
        Logging.debug("Add inst  @ " + Integer.toHexString((int) addr.getOffset()) + " in " + function.toString());
        worklist.push(addr);
    }

    /**
     * @hidden
     * Iterative process for each address inside worklist of this context
     */
    public void loop() {
        PcodeVisitor visitor = new PcodeVisitor(this);
        while (!worklist.isEmpty()) {
            Address addr = worklist.pop();
            if (visitor.visit(addr)) {
                return;
            }
        }
    }

    /**
     * @hidden
     */
    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }

        if (obj instanceof context) {
            context tmp = (context) obj;
            return this.function == tmp.function && Arrays.equals(this.callstring, tmp.callstring);
        }
        return false;
    }

    /**
     * @hidden
     */
    @Override
    public int hashCode() {
        return function.hashCode() + Arrays.hashCode(this.callstring);
    }

    /**
     * @hidden
     */
    @Override
    public String toString() {
        return function.toString() + "["
                + Arrays.stream(callstring).mapToObj(Long::toHexString)
                .collect(Collectors.joining(", ")) + "]";
    }

    /**
     * @hidden
     */
    public static void resetPool() {
        pool.clear();
        active.clear();
        pending.clear();
    }

    /**
     * @hidden
     */
    public static context getEntryContext(Function entryFunction) {
        context tmp = new context(entryFunction);
        context ctx = pool.get(tmp);
        if (ctx != null) {
            return ctx;
        }
        pool.put(tmp, tmp);
        return tmp;
    }

    /**
     * @hidden
     */    
    public static context getContext(context prev, Address callSite, Function tf) {
        context newCtx = new context(tf);
        System.arraycopy(prev.callstring, 1, newCtx.callstring, 0, GlobalState.config.getCallStringK() - 1);
        System.arraycopy(prev.funcs, 1, newCtx.funcs, 0, GlobalState.config.getCallStringK() - 1);
        newCtx.callstring[GlobalState.config.getCallStringK() - 1] = callSite.getOffset();
        newCtx.funcs[GlobalState.config.getCallStringK() - 1] = prev.getFunction();
        context ctx = pool.get(newCtx);
        if (ctx != null) {
            return ctx;
        }
        pool.put(newCtx, newCtx);
        return newCtx;
    }

    /**
     * @hidden
     */
    public static context getContext(Function tf, long[] callstring) { // only for return use
        context newCtx = new context(tf, callstring);
        return pool.get(newCtx);
    }

    /**
     * @hidden
     * @deprecated Improper method for Context class, to be changed
     */
    public static List<context> getContext(Function function) {
        List<context> res = new ArrayList<>();
        for (com.bai.env.context context : pool.keySet()) {
            if (context.getFunction().equals(function)) {
                res.add(context);
            }
        }
        return res;
    }

    /**
     * @hidden
     */
    public static void pushActive(context ctx) {
        if (!active.contains(ctx)) {
            active.push(ctx);
        }
    }

    /**
     * @hidden
     */    
    public static void pushPending(context ctx) {
        if (!pending.contains(ctx)) {
            pending.push(ctx);
        }
    }

    private static context popActive() {
        if (active.isEmpty()) {
            return null;
        }

        return active.pop();
    }

    private static context popPending() {
        if (pending.isEmpty()) {
            return null;
        }
        return pending.pop();
    }

    /**
     * @hidden
     */
    public static context popContext() {
        context ctx = popActive();
        if (ctx == null) {
            ctx = popPending();
        }
        return ctx;
    }

    /**
     * @hidden
     */    
    public static boolean isWait(context ctx) {
        return active.contains(ctx) || pending.contains(ctx);
    }

    /**
     * @hidden
     * Main entry to drive interprocedural analysis with an entry context
     */    
    public static void mainLoop(context entryCtx) {
        current = entryCtx;
        while (current != null) {
            current.loop();
            current = popContext();
            if (current != null) {
                Logging.debug("Switch context: " + current);
            }
        }
    }

    /**
     * @hidden
     * Main entry to drive interprocedural analysis with an entry context and a timer
     */    
    public static void mainLoopTimeout(context entryCtx, long timeout) {
        Logging.info("Analyze started at " + java.time.LocalTime.now() + " with timout " + timeout + "s");
        Runnable task = () -> mainLoop(entryCtx);
        ExecutorService executor = Executors.newSingleThreadExecutor();
        Future<?> future = executor.submit(task);
        try {
            future.get(timeout, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException e) {
            Logging.error(ExceptionUtils.getStackTrace(e));
        } catch (TimeoutException e) {
            Logging.error("Timeout at " + java.time.LocalTime.now() + ". Analysis terminated...");
            future.cancel(true);
        }
        executor.shutdown();
    }

}

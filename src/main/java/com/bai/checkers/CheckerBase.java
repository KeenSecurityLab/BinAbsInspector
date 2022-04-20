package com.bai.checkers;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.KSet;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.pcode.Varnode;
import java.util.ArrayList;
import java.util.List;

/**
 * The base class for all checkers.
 */
public abstract class CheckerBase {

    protected String cwe;
    protected String version;
    protected String description;

    public CheckerBase(String cwe, String version) {
        this.cwe = cwe;
        this.version = version;
    }

    /**
     * Get ALocs of the function parameter.
     * Only use this in offline checker.
     *
     * @param function the function.
     * @param paramIdx the parameter index.
     * @param absEnv the AbsEnv.
     * @return a list of ALocs.
     */
    public static List<ALoc> getParamALocs(Function function, int paramIdx, AbsEnv absEnv) {
        List<ALoc> res = new ArrayList<>();
        Parameter parameter = function.getParameter(paramIdx);
        if (parameter == null) {
            return res;
        }
        Varnode varnode = parameter.getLastStorageVarnode();
        if (varnode == null) {
            return res;
        }
        if (varnode.getAddress().isStackAddress()) {
            if (GlobalState.arch.isX86()) {
                // adjust aLoc to ignore return address on stack
                for (ALoc tmp : ALoc.getStackALocs(varnode, absEnv)) {
                    ALoc adjusted = ALoc.getALoc(tmp.getRegion(),
                            tmp.getBegin() - GlobalState.arch.getDefaultPointerSize(), tmp.getLen());
                    res.add(adjusted);
                }
            } else {
                res = ALoc.getStackALocs(varnode, absEnv);
            }
        } else {
            res.add(ALoc.getALoc(varnode));
        }
        return res;
    }

    /**
     * Get KSet of corresponding parameter.
     * Only use this in offline checker.
     *
     * @param function the function.
     * @param paramIdx the parameter index.
     * @param absEnv the AbsEnv.
     * @return the KSet.
     */
    public static KSet getParamKSet(Function function, int paramIdx, AbsEnv absEnv) {
        KSet res = null;
        for (ALoc aLoc : getParamALocs(function, paramIdx, absEnv)) {
            KSet tmp = absEnv.get(aLoc);
            if (res == null) {
                res = tmp;
            } else {
                KSet union = res.join(tmp);
                res = (union == null) ? res : union;
            }
        }
        return res == null ? KSet.getBot(GlobalState.arch.getDefaultPointerSize() * 8) : res;
    }

    /**
     * Run the checker
     * @return true if there are warnings generated, false otherwise.
     */
    public abstract boolean check();

    /**
     * Get a new report for this checker
     * @param details the detail description of the report.
     * @return the new cwe report.
     */
    public CWEReport getNewReport(String details) {
       return new CWEReport(cwe, version, details);
    }

    /**
     * Get the cwe number.
     * @return the cwe number string.
     */
    public String getCwe() {
        return cwe;
    }

}

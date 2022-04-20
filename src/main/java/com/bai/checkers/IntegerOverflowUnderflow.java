package com.bai.checkers;

import com.bai.env.KSet;
import com.bai.env.TaintMap;
import com.bai.env.TaintMap.Source;
import com.bai.env.funcs.externalfuncs.FgetcFunction;
import com.bai.env.funcs.externalfuncs.FgetsFunction;
import com.bai.env.funcs.externalfuncs.FscanfFunction;
import com.bai.env.funcs.externalfuncs.RandFunction;
import com.bai.env.funcs.externalfuncs.RecvFunction;
import com.bai.env.funcs.externalfuncs.ScanfFunction;
import com.bai.env.funcs.externalfuncs.SscanfFunction;
import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.PcodeOp;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * CWE-190: Integer Overflow or Wraparound <br>
 * CWE-191: Integer Underflow (Wrap or Wraparound)
 */
public class IntegerOverflowUnderflow {

    public static final String CWE190 = "CWE190"; // Integer Overflow
    public static final String CWE191 = "CWE191"; // Integer Underflow
    public static final String VERSION = "0.1";

    private static Set<String> taintSourceFunctionNames;

    static {
        taintSourceFunctionNames = new HashSet<>();
        taintSourceFunctionNames.addAll(ScanfFunction.getStaticSymbols());
        taintSourceFunctionNames.addAll(SscanfFunction.getStaticSymbols());
        taintSourceFunctionNames.addAll(FscanfFunction.getStaticSymbols());
        taintSourceFunctionNames.addAll(FgetsFunction.getStaticSymbols());
        taintSourceFunctionNames.addAll(FgetcFunction.getStaticSymbols());
        taintSourceFunctionNames.addAll(RandFunction.getStaticSymbols());
        taintSourceFunctionNames.addAll(RecvFunction.getStaticSymbols());
    }

    private static CWEReport getOverflowNewReport(String details) {
        return new CWEReport(CWE190, VERSION, details);
    }

    private static CWEReport getUnderflowNewReport(String details) {
        return new CWEReport(CWE191, VERSION, details);
    }

    /**
     * @hidden
     * @param op1
     * @param op2
     * @param pcode
     * @param isOverflow
     * @return
     */
    public static boolean checkTaint(KSet op1, KSet op2, PcodeOp pcode, boolean isOverflow) {
        if (!(op1.isTop() || op2.isTop())) {
            return false;
        }
        if (!(op1.isTaint() || op2.isTaint())) {
            return false;
        }
        long taints1 = op1.getTaints();
        long taints2 = op2.getTaints();
        Address address = Utils.getAddress(pcode);
        Function caller = GlobalState.flatAPI.getFunctionContaining(address);
        if (caller == null) {
            Logging.error("Cannot find function containing the possibly tainted integer operation: " + address);
            return false;
        }
        return reportTaints(taints1, caller.getName(), address, isOverflow)
            || reportTaints(taints2, caller.getName(), address, isOverflow);
    }

    private static boolean reportTaints(long taints, String funcName, Address address, boolean isOverflow) {
        List<Source> taintSourceList = TaintMap.getTaintSourceList(taints);
        for (TaintMap.Source taintSource : taintSourceList) {
            if (!taintSourceFunctionNames.contains(taintSource.getFunction().getName())) {
                continue;
            }
            String type = isOverflow ? "Integer Overflow" : "Integer Underflow";
            String details = "Potential " + type + " due to tainted input from source of "
                    + taintSource.getFunction().getName() + "(" + taintSource.getContext().toString()
                    + ") at inside of \"" + funcName + "()\"";
            CWEReport report = isOverflow ? getOverflowNewReport(details) : getUnderflowNewReport(details);
            report = report.setAddress(address);
            Logging.report(report);
            return true;
        }
        return false;
    }
}
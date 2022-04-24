package com.bai.env.funcs.externalfuncs;

import static ghidra.program.model.pcode.HighFunctionDBUtil.AUTO_CAT;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.util.GlobalState;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.DataTypeSymbol;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;
import com.bai.util.Logging;
import com.bai.util.StringUtils;
import com.bai.util.Utils;
import java.util.ArrayList;
import java.util.Set;

/**
 * The base class of varargs function models.
 */
public abstract class VarArgsFunctionBase extends ExternalFunctionBase {

    protected ArrayList<ParameterDefinitionImpl> defaultParameters = new ArrayList<>();
    private int formatStringParamIndex = 0;

    protected VarArgsFunctionBase(Set<String> symbols) {
        super(symbols);
    }

    protected FunctionDefinition functionDefinition;

    protected void setFormatStringParamIndex(int idx) {
        formatStringParamIndex = idx;
    }

    /**
     * Adapt from HighFunctionDBUtil.writeOverride, but do not clear old symbol.
     * Commit an overriding prototype for a particular call site to the database. The override
     * only applies to the function(s) containing the actual call site. Calls to the same function from
     * other sites are unaffected.  This is used typically either for indirect calls are for calls to
     * a function with a variable number of parameters.
     * @param function is the Function whose call site is being overridden
     * @param callsite is the address of the calling instruction (the call site)
     * @param sig is the overriding function signature
     * @throws InvalidInputException if there are problems committing the override symbol
     */
    private static void writeSignature(Function function, Address callsite, FunctionSignature sig)
            throws InvalidInputException {

        ParameterDefinition[] params = sig.getArguments();
        FunctionDefinitionDataType fsig = new FunctionDefinitionDataType("tmpname");
        fsig.setGenericCallingConvention(sig.getGenericCallingConvention());
        fsig.setArguments(params);
        fsig.setReturnType(sig.getReturnType());
        fsig.setVarArgs(sig.hasVarArgs());

        DataTypeSymbol datsym = new DataTypeSymbol(fsig, "prt", AUTO_CAT);
        Program program = function.getProgram();
        SymbolTable symtab = program.getSymbolTable();
        DataTypeManager dtmanage = program.getDataTypeManager();
        Namespace space = HighFunction.findCreateOverrideSpace(function);
        if (space == null) {
            throw new InvalidInputException("Could not create \"override\" namespace");
        }
        datsym.writeSymbol(symtab, callsite, space, dtmanage, false);
    }

    private FunctionDefinition defineVarArgsSignature(Function callee, Address address, String format) {
        try {
            final int tid = GlobalState.currentProgram.startTransaction("define vargs signature");
            final FunctionDefinition functionDefinition = StringUtils.getFunctionSignature(format, callee);
            Function caller = GlobalState.flatAPI.getFunctionContaining(address);
            if (caller != null) {
                writeSignature(caller, address, functionDefinition);
            }
            GlobalState.currentProgram.endTransaction(tid, true);
            return functionDefinition;
        } catch (Exception e) {
            Logging.error("Fail to define signature for " + callee);
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Process VarArg Signature according to the format string argument.
     * @param pcode the pcode.
     * @param absEnv the AbsEnv.
     * @param calleeFunc the callee functions.
     */
    public void processVarArgsSignature(PcodeOp pcode, AbsEnv absEnv, Function calleeFunc) {
        ALoc retALoc = getReturnALoc(calleeFunc, false);
        if (retALoc == null) {
            Logging.error("Fail to get return ALoc.");
            return;
        }
        String fmtString = null;
        int maxSpecifier = 0;
        KSet bufPtrKSet = getParamKSet(calleeFunc, formatStringParamIndex, absEnv);
        if (bufPtrKSet.isTop()) {
            return;
        }
        for (AbsVal fmtPtr : bufPtrKSet) {
            String tmp = StringUtils.getString(fmtPtr, absEnv);
            if (tmp != null && tmp.chars().filter(ch -> ch == '%').count() > maxSpecifier) {
                fmtString = tmp;
            }
        }
        if (fmtString == null) {
            Logging.debug("Fail to get the format string from arg" + formatStringParamIndex + " @ "
                    + Utils.getAddress(pcode));
            return;
        }
        functionDefinition = getVarArgsSignature(Utils.getAddress(pcode));
        if (functionDefinition == null) {
            functionDefinition = defineVarArgsSignature(calleeFunc, Utils.getAddress(pcode), fmtString);
        }
    }

    @Override
    public void invoke(PcodeOp pcode, AbsEnv inOutEnv, AbsEnv tmpEnv, Context context, Function callFunc) {
        ALoc retALoc = getReturnALoc(callFunc, false);
        if (returnType == IntegerDataType.dataType) {
            inOutEnv.set(retALoc, KSet.getTop(), true);
        } else {
            Logging.warn("Wrong return value type for the input function " + callFunc.getName());
        }
    }

    /**
     * The the vararg function signature at given call site address.
     * @param address the call site address.
     * @return the signature.
     */
    public static FunctionDefinition getVarArgsSignature(Address address) {
        Symbol[] symbols = GlobalState.currentProgram.getSymbolTable().getSymbols(address);
        if (symbols == null || symbols.length == 0 || symbols[0].getSymbolType() != SymbolType.LABEL) {
            return null;
        }
        DataTypeSymbol symbol = HighFunctionDBUtil.readOverride(symbols[0]);
        if (symbol == null) {
            return null;
        }
        return (FunctionDefinition) symbol.getDataType();
    }

}

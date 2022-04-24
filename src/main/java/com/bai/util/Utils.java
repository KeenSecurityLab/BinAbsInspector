package com.bai.util;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.Context;
import com.bai.env.KSet;
import com.bai.env.funcs.FunctionModelManager;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import generic.continues.RethrowContinuesFactory;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.bin.format.elf.ElfException;
import ghidra.app.util.bin.format.elf.ElfHeader;
import ghidra.app.util.bin.format.pe.PortableExecutable;
import ghidra.app.util.bin.format.pe.OptionalHeader;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.util.opinion.PeLoader;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.LabelHistory;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.task.TaskMonitor;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.javimmutable.collections.JImmutableMap.Entry;

/**
 * Utilities.
 */
public class Utils {

    private static boolean setFunctionName(Address entryAddress, String functionName) {
        Function function = GlobalState.flatAPI.getFunctionAt(entryAddress);
        try {
            if (function == null) {
                GlobalState.flatAPI.createFunction(entryAddress, functionName);
            } else {
                function.setName(functionName, SourceType.USER_DEFINED);
            }
        } catch (Exception e) {
            return false;
        }
        return true;
    }

    /**
     * Register external mapping from config.
     * @param program current program
     * @param config the config
     * @return true if success, false otherwise.
     */
    public static boolean registerExternalFunctionsConfig(Program program, Config config) {
        if (config.getExternalMapPath() != null) {
            int txId = program.startTransaction("Set function name");
            try {
                InputStream in = new FileInputStream(GlobalState.config.getExternalMapPath());
                ObjectMapper mapper = new ObjectMapper();
                TypeReference<HashMap<String, String>> typeRef
                        = new TypeReference<>() {
                };
                Map<String, String> tmp = mapper.readValue(in, typeRef);
                for (Map.Entry<String, String> entry : tmp.entrySet()) {
                    Address address = GlobalState.flatAPI.toAddr(entry.getKey());
                    String functionName = entry.getValue();
                    Logging.debug("Map " + address + " -> " + functionName);
                    FunctionModelManager.mapAddress2Symbol(address, functionName);
                    setFunctionName(address, functionName);
                }
            } catch (FileNotFoundException e) {
                Logging.error("Cannot locate external map json file.");
                return false;
            } catch (IOException e) {
                Logging.error("External map config file json format error.");
                return false;
            } finally {
                program.endTransaction(txId, true);
            }
        }
        return true;
    }

    /**
     * Load external fucntion mapping from label history. Only use in GUI mode.
     * @param program current program.
     */
    public static void loadCustomExternalFunctionFromLabelHistory(Program program) {
        ArrayList<LabelHistory> tmp = new ArrayList<>();
        for (Iterator<LabelHistory> it = program.getSymbolTable().getLabelHistory(); it.hasNext(); ) {
            LabelHistory history = it.next();
            tmp.add(history);
        }
        tmp.stream()
                .filter(labelHistory -> labelHistory.getActionID() == LabelHistory.RENAME)
                .sorted(Comparator.comparing(LabelHistory::getModificationDate).reversed())
                .map(labelHistory -> program.getFunctionManager().getFunctionAt(labelHistory.getAddress()))
                .filter(Objects::nonNull)
                .distinct()
                .forEach(function -> {
                            Logging.debug("Map: " + function.getEntryPoint() + " -> " + function.getName());
                            FunctionModelManager.mapAddress2Symbol(function.getEntryPoint(), function.getName());
                        }
                );
    }

    /**
     * Define the main function signature.
     * @param mainFunction the main function.
     * @return true if success, false otherwise.
     */
    public static boolean defineMainFunctionSignature(Function mainFunction) {
        final int tid = GlobalState.currentProgram.startTransaction("define signature");
        FunctionDefinitionDataType mainFuncSignature = new FunctionDefinitionDataType("main");
        ParameterDefinitionImpl[] params = {
                new ParameterDefinitionImpl("argc", IntegerDataType.dataType, "argc"),
                new ParameterDefinitionImpl("argv", PointerDataType.dataType, "argv"),
                new ParameterDefinitionImpl("envp", PointerDataType.dataType, "envp")
        };
        mainFuncSignature.setArguments(params);
        ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(
                mainFunction.getEntryPoint(),
                mainFuncSignature,
                SourceType.USER_DEFINED
        );
        boolean success = cmd.applyTo(GlobalState.currentProgram, TaskMonitor.DUMMY);
        Logging.debug("Define main success: " + success);
        GlobalState.currentProgram.endTransaction(tid, true);
        return success;
    }

    /**
     * Adjust local AbsVal pointer to handle arguments passed on stack.
     * For example, AbsVals with negative offset are pointing to local variables in callee's stack frame,
     * but AbsVals with positive offset are pointing to local variables in caller's stack frame.
     * Because oldSp may have multiple value, so one AbsVal may turn into multiple AbsVal after adjustment.
     * <pre>
     * ┌─────────────┐
     * │    callee   │
     * │ stack frame │-12
     * │             │-8
     * │             │-4
     * ├─────────────┤0 - old sp
     * │    caller   │+4
     * │ stack frame │+8
     * │             │+12
     * │             │
     * └─────────────┘
     * </pre>
     *
     * @param absVal the AbsVal.
     * @param bits the bit length.
     * @return return a List of adjusted AbsVal.
     */
    public static List<AbsVal> adjustLocalAbsVal(AbsVal absVal, Context context, int bits) {
        List<AbsVal> res = new ArrayList<>();
        if (context == null || context.getOldSpKSet() == null) {
            return res;
        }
        if (context.getOldSpKSet().isTop()) {
            return res;
        }
        for (AbsVal oldSp : context.getOldSpKSet()) {
            if (absVal.getRegion().isLocal() && absVal.getOffset() >= 0 && !absVal.isBigVal()) {
                AbsVal adjusted = AbsVal.getPtr(oldSp.getRegion(),
                        oldSp.getValue() + absVal.getOffset());
                res.add(adjusted);
            }
        }
        return res;
    }

    /**
     * Get address of given pcode.
     * @param pcode the pcode.
     * @return the address.
     */
    public static Address getAddress(PcodeOp pcode) {
        return pcode.getSeqnum().getTarget();
    }

    /**
     * Get ordinal from index number.
     * @param i the index.
     * @return the ordinal string.
     */
    public static String getOrdinal(int i) {
        String[] suffixes = new String[]{"th", "st", "nd", "rd", "th", "th", "th", "th", "th", "th"};
        switch (i % 100) {
            case 11:
            case 12:
            case 13:
                return i + "th";
            default:
                return i + suffixes[i % 10];

        }
    }

    /**
     * Merge all taint value from a pointer KSet.
     * @param ptrKSet the pointer KSet.
     * @param absEnv the AbsEnv
     * @return the taint value.
     */
    public static long computePtrTaints(KSet ptrKSet, AbsEnv absEnv) {
        long taints = 0;
        if (ptrKSet.isBot()) {
            return 0;
        }
        if (ptrKSet.isTop()) {
            return ptrKSet.getTaints();
        }
        for (AbsVal srcPtr : ptrKSet) {
            ALoc srcPtrALoc = ALoc.getALoc(srcPtr.getRegion(), srcPtr.getValue(), 1);
            Entry<ALoc, KSet> srcStringEntry = absEnv.getOverlapEntry(srcPtrALoc);
            if (srcStringEntry == null) {
                // no taint from srcString
                continue;
            }
            taints |= srcStringEntry.getValue().getTaints();
        }
        return taints;
    }

    /**
     * Apply taint value to the buffer pointed by a pointer.
     *
     * @param absEnv AbsEnv
     * @param ptr the pointer which point to buffer
     * @param newTaints new taint value
     * @param keptOldTaints whether join old taints with new taints
     */
    public static void taintBuf(AbsEnv absEnv, AbsVal ptr, long newTaints, boolean keptOldTaints) {
        if (ptr.isBigVal()) {
            return;
        }
        ALoc ptrALoc = ALoc.getALoc(ptr.getRegion(), ptr.getValue(), 1);
        Entry<ALoc, KSet> entry = absEnv.getOverlapEntry(ptrALoc);
        if (entry == null) {
            // update BOT with tainted TOP
            absEnv.set(ptrALoc, KSet.getTop(newTaints), true);
        } else {
            KSet bufKSet = entry.getValue();
            long taints = keptOldTaints ? (newTaints | bufKSet.getTaints()) : newTaints;
            bufKSet = bufKSet.setTaints(taints);
            absEnv.set(entry.getKey(), bufKSet, true);
        }
    }

    /**
     * Apply taint value to the buffer pointed by a pointer, and set it with TOP value.
     *
     * @param absEnv AbsEnv
     * @param ptr the pointer which point to buffer
     * @param taints new taint value
     */
    public static void taintBufWithTop(AbsEnv absEnv, AbsVal ptr, long taints) {
        if (ptr.isBigVal()) {
            return;
        }
        KSet topKSet = KSet.getTop(taints);
        ALoc ptrALoc = ALoc.getALoc(ptr.getRegion(), ptr.getValue(), 1);
        Entry<ALoc, KSet> entry = absEnv.getOverlapEntry(ptrALoc);
        if (entry == null) {
            absEnv.set(ptrALoc, topKSet, true);
        } else {
            absEnv.set(entry.getKey(), topKSet, true);
        }
    }

    /**
     * Determine if a function have any call site.
     * @param function the function.
     * @return true if the function does not have any call site (a leaf function), false otherwise.
     */
    public static boolean isLeafFunction(Function function) {
        return function.getCalledFunctions(TaskMonitor.DUMMY).size() == 0;
    }


    /**
     * Checks whether z3 solver is installed properly on this machine.
     * @return true if z3 solver works fine, false otherwise.
     */
    public static boolean checkZ3Installation() {
        try {
            com.microsoft.z3.Context z3Context = new com.microsoft.z3.Context();
            z3Context.close();
            return true;
        } catch (UnsatisfiedLinkError e) {
            Logging.error(
                    "Cannot detect z3 solver library, please check your z3 solver installation "
                            + "or disable z3 solver in configuration.");
            return false;
        }
    }

    /**
     * Get all references which call to the function with given symbol names.
     * @param symbolNames a list of symbol names.
     * @return a list of references.
     */
    public static List<Reference> getReferences(List<String> symbolNames) {
        SymbolIterator symbolIterator = Optional.ofNullable(
                GlobalState.currentProgram.getSymbolTable()).map(SymbolTable::getSymbolIterator).orElse(null);
        if (symbolIterator == null) {
            Logging.error("Empty symbol table");
            return new ArrayList<>();
        }
        return Stream.generate(() -> null)
                .takeWhile(x -> symbolIterator.hasNext())
                .map(n -> symbolIterator.next())
                .filter(symbol -> symbolNames.contains(symbol.getName()))
                // If a function symbol has a reference with a type RefType.THUNK, then it is a thunk function,
                // and we skip those thunk functions.
                .filter(symbol -> Arrays.stream(symbol.getReferences())
                        .noneMatch(reference -> reference.getReferenceType() == RefType.THUNK))
                .flatMap(symbol -> Arrays.stream(symbol.getReferences()))
                .collect(Collectors.toList());
    }

    /**
     * Get the entry function of the ELF/PE executable.
     * @return
     */
    public static Function getEntryFunction() {
        try {
            MemoryByteProvider provider = new MemoryByteProvider(GlobalState.currentProgram.getMemory(),
                    GlobalState.currentProgram.getMinAddress());
            
            Address entryAddress;
            String executableFormat = GlobalState.currentProgram.getExecutableFormat();
            
            switch (executableFormat) {
                case ElfLoader.ELF_NAME: {
                    ElfHeader header = ElfHeader.createElfHeader(RethrowContinuesFactory.INSTANCE, provider);
                    entryAddress = GlobalState.flatAPI.toAddr(header.e_entry());
                    if (entryAddress.subtract(GlobalState.currentProgram.getImageBase()) < 0) {
                        // handle PIE ELF with non-zero base address
                        entryAddress = entryAddress.add(GlobalState.currentProgram.getImageBase().getOffset());
                    }
                }
                break;

                case PeLoader.PE_NAME: {
                    PortableExecutable pe = PortableExecutable.createPortableExecutable(
                            RethrowContinuesFactory.INSTANCE, provider, PortableExecutable.SectionLayout.MEMORY);
                    OptionalHeader header = pe.getNTHeader().getOptionalHeader();
                    entryAddress = GlobalState.flatAPI.toAddr(header.getAddressOfEntryPoint());
                    entryAddress = entryAddress.add(GlobalState.currentProgram.getImageBase().getOffset());
                }
                break;

                default:
                    throw new Exception("Unsupported file format.");
            }

            return GlobalState.flatAPI.getFunctionAt(entryAddress);
        } catch (Exception e) {
            Logging.error(e.getMessage());
            return null;
        }
    }
}

package com.bai.checkers;

import com.bai.util.CWEReport;
import com.bai.util.GlobalState;
import com.bai.util.Logging;
import com.bai.util.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Set;

/**
 * CWE-190: Integer Overflow or Wraparound
 */
public class CWE190 extends CheckerBase {

    private static final Set<String> interestingSymbols = Set.of("malloc", "xmalloc", "calloc", "realloc");

    public CWE190() {
        super("CWE190", "0.1");
        description = "Integer Overflow or Wraparound: The software performs a calculation that "
                + "can produce an integer overflow or wraparound, when the logic assumes that the resulting value "
                + "will always be larger than the original value. This can introduce other weaknesses "
                + "when the calculation is used for resource management or execution control.";
    }

    private boolean checkCodeBlock(CodeBlock codeBlock, Reference ref) {
        boolean foundWrapAround = false;
        for (Address address : codeBlock.getAddresses(true)) {
            Instruction instruction = GlobalState.flatAPI.getInstructionAt(address);
            if (instruction == null) {
                continue;
            }
            for (PcodeOp pCode : instruction.getPcode(true)) {
                if (pCode.getOpcode() == PcodeOp.INT_LEFT || pCode.getOpcode() == PcodeOp.INT_MULT) {
                    foundWrapAround = true;
                }
                if (pCode.getOpcode() == PcodeOp.CALL && foundWrapAround && pCode.getInput(0).getAddress()
                        .equals(ref.getToAddress())) {
                    CWEReport report = getNewReport(
                            "(Integer Overflow or Wraparound) Potential overflow "
                                    + "due to multiplication before call to malloc").setAddress(
                            Utils.getAddress(pCode));
                    Logging.report(report);
                    return true;
                }
            }
        }
        return false;
    }

    @Override
    public boolean check() {
        boolean hasWarning = false;
        try {
            BasicBlockModel basicBlockModel = new BasicBlockModel(GlobalState.currentProgram);
            for (Reference reference : Utils.getReferences(new ArrayList<>(interestingSymbols))) {
                Logging.debug(reference.getFromAddress() + "->" + reference.getToAddress());
                for (CodeBlock codeBlock : basicBlockModel.getCodeBlocksContaining(reference.getFromAddress(),
                        TaskMonitor.DUMMY)) {
                    hasWarning |= checkCodeBlock(codeBlock, reference);
                }
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
        return hasWarning;
    }
}

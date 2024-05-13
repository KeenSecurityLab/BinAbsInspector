package com.bai.util;

import com.bai.env.ALoc;
import com.bai.env.AbsVal;
import com.bai.env.KSet;
import com.bai.env.region.Global;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;

/**
 * The Architecture specific utilities.
 */
public class Architecture {
    // from: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/ARM/data/languages/ARM.sinc#L10
    private static final int[] ARMV7_FLAG_INDEXES = {
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
        0xB0
    };
    private static final int ARMV7_SP_INDEX = 0x54;

    // from: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/AARCH64/data/languages/AARCH64instructions.sinc#L62
    private static final int[] ARMV8_FLAG_INDEXES = {
        0x101, 0x102, 0x103, 0x104, 0x105, 0x106, 0x107, 0x108
    };
    private static final int ARMV8_SP_INDEX = 0x8;

    // from: https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/x86/data/languages/ia.sinc#L38
    private static final int[] X86_FLAG_INDEXES = {
        0x200, 0x201, 0x202, 0x203, 0x204, 0x205, 0x206, 0x207,
        0x208, 0x209, 0x20A, 0x20B, 0x20C, 0x20D, 0x20E, 0x20F,
        0x210, 0x211, 0x212, 0x213, 0x214, 0x215
    };
    private static final int X86_32_SP_INDEX = 0x10;
    private static final int X86_64_SP_INDEX = 0x20;

    private String processor;
    private boolean isLittleEndian;
    private int wordBits;
    private int defaultPointerSize;
    private int pcIndex;
    private int[] flagIndexes;
    private int spIndex;

    public Architecture(Program program) {
        processor = program.getLanguage().getProcessor().toString();
        isLittleEndian = !program.getMemory().isBigEndian();
        wordBits = program.getAddressFactory().getDefaultAddressSpace().getSize();
        defaultPointerSize = program.getDefaultPointerSize();
        pcIndex = program.getLanguage().getProgramCounter().getOffset();

        switch (processor) {
            case "ARM":
                flagIndexes = ARMV7_FLAG_INDEXES;
                spIndex = ARMV7_SP_INDEX;
                break;
            case "AARCH64":
                flagIndexes = ARMV8_FLAG_INDEXES;
                spIndex = ARMV8_SP_INDEX;
                break;
            case "x86":
                flagIndexes = X86_FLAG_INDEXES;
                if (defaultPointerSize == 4) {
                    spIndex = X86_32_SP_INDEX;
                    break;
                } else if (defaultPointerSize == 8) {
                    spIndex = X86_64_SP_INDEX;
                    break;
                }
                // fallthrough to error if invalid defaultPointerSize
            default:
                Logging.error("Unsupported architecture.");
                System.exit(-1);
        }
    }

    /**
     * Checks if the architecture of current program is little endian.
     * @return true if it is little endian, false otherwise.
     */
    public boolean isLittleEndian() {
        return isLittleEndian;
    }


    /**
     * Get the word bits of current architecture.
     * @return the word bits.
     */
    public int getWordBits() {
        return wordBits;
    }

    /**
     * Get default pointer size of current program
     * @return the pointer size.
     */
    public int getDefaultPointerSize() {
        return defaultPointerSize;
    }

    /**
     * Get the sp (stack pointer) register index.
     * @return the sp register index.
     */
    public int getSpIndex() {
       return spIndex;
    }

    /**
     * Get the pc (program counter) register index.
     * @return the pc register index.
     */
    public int getPcIndex() {
        return pcIndex;
    }

    /**
     * Get the array of flag regstger indexes.
     * @return an array of flag register indexes.
     */
    public int[] getFlagIndexes() {
        return flagIndexes;
    }

    /**
     * Checks if current program is x86 architecture (32 or 64 bits).
     * @return true if it is x86, false otherwise
     */
    public boolean isX86() {
        return processor.equalsIgnoreCase("x86");
    }

    /**
     * Checks if current program is ARM architecture (32 bits).
     * 
     * @return true if it is ARM 32 bits, false otherwise
     */
    public boolean isArm32() {
        return processor.equalsIgnoreCase("ARM");
    }

    /**
     * Checks if current program is AArch64 architecture (64 bits).
     * 
     * @return true if it is AArch64, false otherwise
     */
    public boolean isAArch64() {
        return processor.equalsIgnoreCase("AARCH64");
    }

    /**
     * Get the KSet of pc register.
     * @param currentAddress address of current instruction.
     * @return the KSet.
     */
    public KSet getPcKSet(Address currentAddress) {
        long pcValue;
        KSet pcKSet = new KSet(defaultPointerSize * 8);
        switch (processor) {
            case "ARM":
                Register tMode = GlobalState.currentProgram.getProgramContext().getRegister("TMode");
                boolean isThumb = GlobalState.currentProgram.getProgramContext().getRegisterValue(tMode, currentAddress)
                        .getUnsignedValue().testBit(0);
                if (isThumb) {
                    pcValue = currentAddress.getOffset() & 0xFFFFFFFCL + 4;
                } else {
                    pcValue = currentAddress.getOffset() + 8;
                }
                break;
            case "AARCH64":
                pcValue = currentAddress.getOffset();
                break;
            case "x86":
                pcValue = GlobalState.flatAPI.getInstructionAfter(currentAddress).getAddress().getOffset();
                break;
            default:
                Logging.error("getPCKSet(): unsupported architecture");
                return pcKSet;
        }
        pcKSet = pcKSet.insert(AbsVal.getPtr(Global.getInstance(), pcValue));
        return pcKSet;
    }

    /**
     * Checks if the register is a callee saved register.
     * 
     * @param aLoc abstract location of the register.
     * @return the KSet.
     */
    public boolean isCalleeSavedRegister(ALoc aLoc) {
        switch (processor) {
            case "ARM":
                return isArm32SavedRegister(aLoc);
            case "AARCH64":
                return isAArch64SavedRegister(aLoc);
            case "x86":
            default:
                return false;
        }
    }

    /**
     * Checks if the register is a callee saved register of Arm 32 architecture.
     * Checks if the register is in range r4 - r11, but not r9.
     * See
     * https://github.com/NationalSecurityAgency/ghidra/blob/ef3e74b6d3cb9e7ce1ccef20c8660dcb5346066e/Ghidra/Processors/ARM/data/languages/ARM.sinc#L10
     * See also:
     * https://github.com/ARM-software/abi-aa/blob/60a8eb8c55e999d74dac5e368fc9d7e36e38dda4/aapcs32/aapcs32.rst
     * 
     * @param aLoc abstract location of the register.
     * @return the KSet.
     */
    public static boolean isArm32SavedRegister(ALoc aLoc) {
        if (!aLoc.getRegion().isReg()) {
            return false;
        }
        long start = aLoc.getBegin();
        long end = start + aLoc.getLen();
        // r9
        if (start == 0x44 && end == 0x48) {
            return false;
        }
        // r4 (0x30) - r11
        if (start >= 0x30 && end <= 0x50) {
            return true;
        }
        return false;
    }

    /**
     * Checks if the register is a callee saved register of AArch64 architecture.
     * Checks if the register is in range x19 - x29.
     * See
     * https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors/AARCH64/data/languages/AARCH64instructions.sinc#L448
     * 
     * @param aLoc abstract location of the register.
     * @return the KSet.
     */
    public static boolean isAArch64SavedRegister(ALoc aLoc) {
        if (!aLoc.getRegion().isReg()) {
            return false;
        }
        long start = aLoc.getBegin();
        long end = start + aLoc.getLen();
        // r19 - r29
        if (start >= 0x4098 && end <= 0x40F0) {
            return true;
        }
        return false;
    }
}

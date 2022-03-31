package com.bai.env;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.Varnode;
import com.bai.env.region.Global;
import com.bai.env.region.Reg;
import com.bai.env.region.RegionBase;
import com.bai.env.region.Unique;
import com.bai.util.GlobalState;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Abstract Location **/
public class ALoc implements Comparable<ALoc> {

    protected RegionBase region;

    protected long begin;
    
    protected int len;

    private static Map<ALoc, ALoc> pool = new HashMap<>();

    /**
     * Constructor of ALoc
     * @param region Region
     * @param begin begin >= 0
     * @param len len > 0, length of bytes
     */
    private ALoc(RegionBase region, long begin, int len) {
        assert (len != 0);
        this.region = region;
        this.begin = begin;
        this.len = len;
    }

    /**
     * Getter for the region of ALoc
     */
    public RegionBase getRegion() {
        return region;
    }

    /**
     * Getter for the length of ALoc
     */
    public int getLen() {
        return len;
    }

    /**
     * Getter for the begin offset inside the region of ALoc
     */
    public long getBegin() {
        return begin;
    }

    /**
     * Wrapper for factory method of ALoc
     */
    public static ALoc getALoc(RegionBase region, long begin, long len) {
        return getALoc(region, begin, (int) len);
    }

    /**
     * Factory method for creating ALoc
     * @param region Region for this ALoc
     * @param begin begin offset inside the above region for this ALoc
     * @param len length for this ALOc
     * @return Created ALoc
     */
    public static ALoc getALoc(RegionBase region, long begin, int len) {
        ALoc newALoc = new ALoc(region, begin, len);
        ALoc oldALoc = pool.get(newALoc);
        if (oldALoc == null) {
            pool.put(newALoc, newALoc);
            return newALoc;
        }
        return oldALoc;
    }

    /**
     * Create ALoc from Ghidra's Varnode. 
     * @param varnode Ghidra's varnode describing a variable. Constant varnode is not accepted
     * @return Corresponding ALoc
     */
    public static ALoc getALoc(Varnode varnode) {
        if (varnode.isRegister()) {
            return getALoc(Reg.getInstance(), varnode.getOffset(), varnode.getSize());
        }
        if (varnode.isAddress()) {
            return getALoc(Global.getInstance(), varnode.getOffset(), varnode.getSize());
        }
        if (varnode.isUnique()) {
            return getALoc(Unique.getInstance(), varnode.getOffset(), varnode.getSize());
        }
        return null;
    }

    /**
     * Get ALoc for stack pointer register
     */
    public static ALoc getSPALoc() {
        return ALoc.getALoc(Reg.getInstance(), GlobalState.arch.getSpIndex(), GlobalState.arch.getDefaultPointerSize());
    }


    /**
     * @hidden
     * @deprecated Ugly method, to be changed 
     */
    public static List<ALoc> getStackALocs(Varnode varnode, AbsEnv absEnv) {
        List<ALoc> res = new ArrayList<>();
        ALoc spALoc = ALoc.getSPALoc();
        KSet spKSet = absEnv.get(spALoc);
        if (!spKSet.isNormal()) {
            return res;
        }
        for (AbsVal spAbsVal : spKSet) {
            ALoc tmp = getALoc(spAbsVal.getRegion(), spAbsVal.getValue() + varnode.getOffset(), varnode.getSize());
            res.add(tmp);
        }
        return res;
    }

    /**
     * @hidden
     */
    public static void resetPool() {
        pool.clear();
    }

    /**
     * Check if this ALoc will exactly overlap other ALoc.
     * exactly overlap:
     * <pre>
     * {@code
     * AAAAAAAA <- old ALoc
     * BBBBBBBB <- this ALoc
     * }
     * </pre>
     * @param old ALoc
     * @return true if exactly overlapped, false otherwise.
     */
    protected boolean isExactly(ALoc old) {
        return begin == old.begin && len == old.len;
    }

    /**
     * Check if this ALoc will partially overlap other ALoc from left size.
     * left partially overlap:
     * <pre>
     * {@code
     * ----AAAAAAAA <- old ALoc
     * BBBBBBBB---- <- this ALoc
     * }
     * </pre>
     * @param old ALoc
     * @return true if partially overlapped from left size, false otherwise.
     */
    protected boolean isLeftPartialOverlap(ALoc old) {
        long end = begin + len;
        long oldEnd = old.begin + old.len;
        return begin < old.begin && end > old.begin && end < oldEnd;
    }

    /**
     * Check if this ALoc will partially overlap other ALoc from right size.
     * right partially overlap:
     * <pre>
     * {@code
     * AAAAAAAA---- <- old ALoc
     * ----BBBBBBBB <- this ALoc
     * }
     * </pre>
     * @param old ALoc
     * @return true if partially overlapped from right size, false otherwise.
     */
    protected boolean isRightPartialOverlap(ALoc old) {
        long end = begin + len;
        long oldEnd = old.begin + old.len;
        return old.begin < begin && oldEnd > begin && oldEnd < end;
    }

    /**
     * Check if this ALoc will fully overlap other ALoc.
     * fully overlap:
     * <pre>
     * {@code
     * 1.
     * ----AAAA---- <- old ALoc
     * BBBBBBBBBBBB <- this ALoc
     * 2.
     * ----AAAAAAAA <- old ALoc
     * BBBBBBBBBBBB <- this ALoc
     * 3.
     * AAAAAAAA---- <- old ALoc
     * BBBBBBBBBBBB <- this ALoc
     * }
     * </pre>
     * @param old ALoc
     * @return true if fully overlapped, false otherwise.
     */
    protected boolean isFullyOverlap(ALoc old) {
        long end = begin + len;
        long oldEnd = old.begin + old.len;
        if (begin == old.begin && len == old.len) {
            return false;
        }
        return begin <= old.begin && end >= oldEnd;
    }

    /**
     * Check if this ALoc will overlap subset of other ALoc.
     * subset overlap:
     * <pre>
     * {@code
     * 1.
     * AAAAAAAAAAAA <- old ALoc
     * ----BBBB---- <- this ALoc
     * 2.
     * AAAAAAAAAAAA <- old ALoc
     * ----BBBBBBBB <- this ALoc
     * 3.
     * AAAAAAAAAAAA <- old ALoc
     * BBBBBBBB---- <- this ALoc
     * }
     * </pre>
     * @param old ALoc
     * @return true if overlap subset, false otherwise.
     */
    protected boolean isSubsetOverlap(ALoc old) {
        long end = begin + len;
        long oldEnd = old.begin + old.len;
        if (begin == old.begin && len == old.len) {
            return false;
        }
        return old.begin <= begin && oldEnd >= end;
    }

    /**
     * Check if this ALoc is PC register or not
     */
    public boolean isPC() {
        return region == Reg.getInstance() && begin == GlobalState.arch.getPcIndex();
    }

    /**
     * Check if this ALoc is SP register or not
     */
    public boolean isSP() {
        return region == Reg.getInstance() && begin == GlobalState.arch.getSpIndex();
    }

    /**
     * Check if this ALoc is one of flag registers or not
     */
    public boolean isFlag() {
        if (region != Reg.getInstance()) {
            return false;
        }
        return Arrays.stream(GlobalState.arch.getFlagIndexes()).anyMatch(idx -> idx == begin);
    }

    /**
     * Check if this ALoc reprensents a readable global address or not
     */
    public boolean isGlobalReadable() {
        if (!region.isGlobal()) {
            return false;
        }
        Address address = GlobalState.flatAPI.toAddr(begin);
        MemoryBlock memoryBlock = GlobalState.flatAPI.getMemoryBlock(address);
        if (memoryBlock == null) {
            return false;
        }
        return memoryBlock.isRead();
    }

    /**
     * Check if this ALoc reprensents a writable global address or not
     */
    public boolean isGlobalWritable() {
        if (!region.isGlobal()) {
            return false;
        }
        Address address = GlobalState.flatAPI.toAddr(begin);
        MemoryBlock memoryBlock = GlobalState.flatAPI.getMemoryBlock(address);
        if (memoryBlock == null) {
            return false;
        }
        return memoryBlock.isWrite();
    }

    /**
     * @hidden
     */
    @Override
    public int compareTo(ALoc rhs) {
        if (this.region.equals(rhs.region)) {
            long begin1 = this.begin;
            long end1 = this.begin + this.len;
            long begin2 = rhs.begin;
            long end2 = rhs.begin + rhs.len;
            if (end1 <= begin2) {
                return -1;
            } else if (end2 <= begin1) {
                return 1;
            } else {
                return 0;
            }
        }
        if (this.region.hashCode() > rhs.region.hashCode()) {
            return 1;
        }
        return -1;
    }

    /**
     * @hidden
     */
    public int hashCode() {
        return region.hashCode() + (int) begin;
    }

    /**
     * @hidden
     */
    public boolean equals(Object rhs) {
        if (this == rhs) {
            return true;
        }
        if (rhs instanceof ALoc) {
            ALoc other = (ALoc) rhs;
            return this.region.equals(other.region) && this.begin == other.begin && this.len == other.len;
        }
        return false;
    }

    /**
     * @hidden
     */
    @Override
    public String toString() {
        if (region.isReg()) {
            Register register = GlobalState.currentProgram.getLanguage()
                    .getRegister(GlobalState.flatAPI.getAddressFactory().getRegisterSpace(), begin, len);
            if (register != null) {
                return register.toString();
            } else {
                return "UNKNOWN_REG[" + Long.toHexString(begin) + "h," + Long.toHexString(begin + len) + "h]";
            }
        } else {
            return region.toString() + "[" + Long.toHexString(begin) + "h," + Long.toHexString(begin + len) + "h]";
        }
    }

}
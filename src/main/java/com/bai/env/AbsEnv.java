package com.bai.env;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.MemoryAccessException;
import com.bai.env.region.Global;
import com.bai.env.region.Reg;
import com.bai.env.region.RegionBase;
import com.bai.util.GlobalState;
import org.javimmutable.collections.Holder;
import org.javimmutable.collections.JImmutableMap.Entry;
import org.javimmutable.collections.tree.JImmutableTreeMap;

public class AbsEnv {

    private JImmutableTreeMap<ALoc, KSet> envMap;

    public AbsEnv() {
        envMap = JImmutableTreeMap.of();
    }

    public AbsEnv(AbsEnv other) {
        envMap = other.envMap;
    }

    public AbsEnv(JImmutableTreeMap<ALoc, KSet> envMap) {
        this.envMap = envMap;
    }

    public JImmutableTreeMap<ALoc, KSet> getEnvMap() {
        return envMap;
    }

    public AbsEnv join(AbsEnv other) {
        AbsEnv res = new AbsEnv(this);
        for (Entry<ALoc, KSet> entry : other.envMap) {
            res.set(entry.getKey(), entry.getValue(), false);
        }
        if (!res.envMap.equals(this.envMap)) {
            return res;
        }
        // unchanged
        return null;
    }

    /**
     * Set the ALoc when it has not bound with KSet before.
     *
     * @param aLoc the target abstract location.
     * @param oldKSet old KSet bound with the target ALoc.
     * @param newKSet new KSet to be bound with ALoc.
     * @param isStrongUpdate strong update or not.
     */

    private void setEmptyALoc(ALoc aLoc, KSet oldKSet, KSet newKSet, boolean isStrongUpdate) {
        assert envMap.findEntry(aLoc).isEmpty();
        if (isStrongUpdate) {
            if (!newKSet.isBot()) {
                envMap = envMap.assign(aLoc, newKSet);
            }
        } else {
            assert (!oldKSet.isBot());
            KSet tmp = oldKSet.join(newKSet);
            if (tmp != null) {
                assert (!tmp.isBot());
                envMap = envMap.assign(aLoc, tmp);
            } else {
                envMap = envMap.assign(aLoc, oldKSet);
            }
        }
    }

    /**
     * Set the ALoc when it already binds with a KSet.
     *
     * @param aLoc the target abstract location.
     * @param oldKSet old KSet bound with the target ALoc.
     * @param newKSet new KSet to be bound with ALoc.
     * @param isStrongUpdate strong update or not.
     */
    private void setFilledALoc(ALoc aLoc, KSet oldKSet, KSet newKSet, boolean isStrongUpdate) {
        assert envMap.findEntry(aLoc).isFilled();
        if (isStrongUpdate) {
            if (newKSet.isBot()) {
                envMap = envMap.delete(aLoc);
            } else if (!newKSet.equals(oldKSet)) {
                envMap = envMap.assign(aLoc, newKSet);
            }
        } else {
            assert (!oldKSet.isBot());
            KSet tmp = oldKSet.join(newKSet);
            if (tmp != null) {
                assert (!tmp.isBot());
                envMap = envMap.assign(aLoc, tmp);
            }
        }
    }

    private KSet loadFromProgram(ALoc aLoc) {
        assert aLoc.region.isGlobal();
        AbsVal tmp;
        try {
            Address address = GlobalState.flatAPI.toAddr(aLoc.begin);
            byte[] buf = GlobalState.flatAPI.getBytes(address, aLoc.len);
            tmp = AbsVal.bytesToAbsVal(Global.getInstance(), buf);
        } catch (MemoryAccessException | AddressOutOfBoundsException e) {
            tmp = null;
        }
        KSet res = new KSet(aLoc.len * 8);
        if (tmp != null) {
            res = res.insert(tmp);
        }
        return res;
    }

    public void set(ALoc newALoc, KSet newKSet, boolean isStrongUpdate) {
        if (!newKSet.isTop()) {
            assert newALoc.len * 8 == newKSet.getBits();
        }

        Holder<Entry<ALoc, KSet>> holder = envMap.findEntry(newALoc);
        if (holder.isEmpty()) {
            // none overlap
            if (!newKSet.isBot()) {
                envMap = envMap.assign(newALoc, newKSet);
            }
        } else {
            Entry<ALoc, KSet> oldEntry = holder.getValue();
            ALoc oldALoc = oldEntry.getKey();
            KSet oldKSet = oldEntry.getValue();

            long newBegin = newALoc.begin;
            long newEnd = newALoc.begin + newALoc.len;
            long oldBegin = oldALoc.begin;
            long oldEnd = oldALoc.begin + oldALoc.len;

            assert oldALoc.region.equals(newALoc.region);
            RegionBase region = newALoc.region;

            if (newALoc.isExactly(oldALoc)) {
                // AAAAAAAA
                // BBBBBBBB
                setFilledALoc(newALoc, oldKSet, newKSet, isStrongUpdate);
            } else if (newALoc.isLeftPartialOverlap(oldALoc)) {
                // ┌─────────────newRemainALoc
                // │   ┌─────────interALoc
                // │   │   ┌─────oldRemainALoc
                // │   │   │
                // ----AAAAAAAA
                // BBBBBBBB----
                final ALoc interALoc = ALoc.getALoc(region, oldBegin, newEnd - oldBegin);
                final ALoc oldRemainALoc = ALoc.getALoc(region, newEnd, oldEnd - newEnd);
                final ALoc newRemainALoc = ALoc.getALoc(region, newBegin, oldBegin - newBegin);

                final KSet oldInterKSet = oldKSet.truncate(0, newEnd - oldBegin);
                final KSet newInterKSet = newKSet.truncate(oldBegin - newBegin, newEnd - oldBegin);
                final KSet newRemainKSet = newKSet.truncate(0, oldBegin - newBegin);
                final KSet oldRemainKSet = oldKSet.truncate(newEnd - oldBegin, oldEnd - newEnd);

                envMap = envMap.delete(oldALoc);
                setEmptyALoc(interALoc, oldInterKSet, newInterKSet, isStrongUpdate);
                envMap = envMap.assign(oldRemainALoc, oldRemainKSet);
                set(newRemainALoc, newRemainKSet, isStrongUpdate);

            } else if (newALoc.isRightPartialOverlap(oldALoc)) {
                // ┌─────────────oldRemainALoc
                // │   ┌─────────interALoc
                // │   │   ┌─────newRemainALoc
                // │   │   │
                // AAAAAAAA----
                // ----BBBBBBBB
                final ALoc interALoc = ALoc.getALoc(region, newBegin, oldEnd - newBegin);
                final ALoc oldRemainALoc = ALoc.getALoc(region, oldBegin, newBegin - oldBegin);
                final ALoc newRemainALoc = ALoc.getALoc(region, oldEnd, newEnd - oldEnd);

                final KSet oldInterKSet = oldKSet.truncate(newBegin - oldBegin, oldEnd - newBegin);
                final KSet newInterKSet = newKSet.truncate(0, oldEnd - newBegin);
                final KSet newRemainKSet = newKSet.truncate(oldEnd - newBegin, newEnd - oldEnd);
                final KSet oldRemainKSet = oldKSet.truncate(0, newBegin - oldBegin);

                envMap = envMap.delete(oldALoc);
                setEmptyALoc(interALoc, oldInterKSet, newInterKSet, isStrongUpdate);
                envMap = envMap.assign(oldRemainALoc, oldRemainKSet);
                set(newRemainALoc, newRemainKSet, isStrongUpdate);

            } else if (newALoc.isFullyOverlap(oldALoc)) {
                // ┌─────────────leftALoc
                // │   ┌─────────interALoc
                // │   │   ┌─────rightALoc
                // │   │   │
                // ----AAAA----
                // BBBBBBBBBBBB
                final ALoc interALoc = oldALoc;
                final KSet oldInterKSet = oldKSet;
                final KSet newInterKSet = newKSet.truncate(oldBegin - newBegin, oldEnd - oldBegin);

                setFilledALoc(interALoc, oldInterKSet, newInterKSet, isStrongUpdate);
                if (newBegin != oldBegin) {
                    ALoc leftALoc = ALoc.getALoc(region, newBegin, oldBegin - newBegin);
                    KSet leftKSet = newKSet.truncate(0, oldBegin - newBegin);
                    set(leftALoc, leftKSet, isStrongUpdate);
                }

                if (newEnd != oldEnd) {
                    ALoc rightALoc = ALoc.getALoc(region, oldEnd, newEnd - oldEnd);
                    KSet rightKSet = newKSet.truncate(oldEnd - newBegin, newEnd - oldEnd);
                    set(rightALoc, rightKSet, isStrongUpdate);
                }

            } else if (newALoc.isSubsetOverlap(oldALoc)) {
                // ┌─────────────leftALoc
                // │   ┌─────────interALoc
                // │   │   ┌─────rightALoc
                // │   │   │
                // AAAAAAAAAAAA
                // ----BBBB----
                final ALoc interAloc = newALoc;
                final KSet oldInterKSet = oldKSet.truncate(newBegin - oldBegin, newEnd - newBegin);
                final KSet newInterKSet = newKSet;

                envMap = envMap.delete(oldALoc);
                setEmptyALoc(interAloc, oldInterKSet, newInterKSet, isStrongUpdate);
                if (newBegin != oldBegin) {
                    ALoc leftALoc = ALoc.getALoc(region, oldBegin, newBegin - oldBegin);
                    KSet leftKSet = oldKSet.truncate(0, newBegin - oldBegin);
                    envMap = envMap.assign(leftALoc, leftKSet);
                }
                if (newEnd != oldEnd) {
                    ALoc rightALoc = ALoc.getALoc(region, newEnd, oldEnd - newEnd);
                    KSet rightKSet = oldKSet.truncate(newEnd - oldBegin, oldEnd - newEnd);
                    envMap = envMap.assign(rightALoc, rightKSet);
                }
            }

        }
    }

    public KSet get(ALoc aLoc) {

        Holder<Entry<ALoc, KSet>> holder = envMap.findEntry(aLoc);
        if (holder.isEmpty()) {
            if (aLoc.region.isGlobal()) {
                return loadFromProgram(aLoc);
            }
            return new KSet(aLoc.len * 8);
        }

        Entry<ALoc, KSet> oldEntry = holder.getValue();
        ALoc oldALoc = oldEntry.getKey();
        KSet oldKSet = oldEntry.getValue();

        long newBegin = aLoc.begin;
        long newEnd = aLoc.begin + aLoc.len;
        long oldBegin = oldALoc.begin;
        long oldEnd = oldALoc.begin + oldALoc.len;

        RegionBase region = aLoc.region;
        assert aLoc.region.equals(oldALoc.region);

        assert !oldKSet.isBot();

        if (aLoc.isExactly(oldALoc)) {
            // AAAAAAAA
            // BBBBBBBB
            return oldKSet;
        } else if (aLoc.isLeftPartialOverlap(oldALoc)) {
            // ┌─────────────newRemainALoc
            // │   ┌─────────interALoc
            // │   │   ┌─────oldRemainALoc
            // │   │   │
            // ----AAAAAAAA
            // BBBBBBBB----
            ALoc newRemainALoc = ALoc.getALoc(region, newBegin, oldBegin - newBegin);
            KSet interKSet = oldKSet.truncate(0, newEnd - oldBegin);
            KSet newRemainKSet = get(newRemainALoc);
            return newRemainKSet.concat(interKSet);

        } else if (aLoc.isRightPartialOverlap(oldALoc)) {
            // ┌─────────────oldRemainALoc
            // │   ┌─────────interALoc
            // │   │   ┌─────newRemainALoc
            // │   │   │
            // AAAAAAAA----
            // ----BBBBBBBB
            ALoc newRemainALoc = ALoc.getALoc(region, oldEnd, newEnd - oldEnd);
            KSet interKSet = oldKSet.truncate(newBegin - oldBegin, oldEnd - newBegin);
            KSet newRemainKSet = get(newRemainALoc);
            return interKSet.concat(newRemainKSet);
        } else if (aLoc.isFullyOverlap(oldALoc)) {
            // ┌─────────────leftALoc
            // │   ┌─────────interALoc
            // │   │   ┌─────rightALoc
            // │   │   │
            // ----AAAA----
            // BBBBBBBBBBBB
            KSet res = oldKSet;
            if (newBegin != oldBegin) {
                ALoc leftALoc = ALoc.getALoc(region, newBegin, oldBegin - newBegin);
                KSet leftKSet = get(leftALoc);
                res = leftKSet.concat(res);
            }
            if (newEnd != oldEnd) {
                ALoc rightALoc = ALoc.getALoc(region, oldEnd, newEnd - oldEnd);
                KSet rightKSet = get(rightALoc);
                res = res.concat(rightKSet);
            }
            return res;
        } else if (aLoc.isSubsetOverlap(oldALoc)) {
            // ┌─────────────leftALoc
            // │   ┌─────────interALoc
            // │   │   ┌─────rightALoc
            // │   │   │
            // AAAAAAAAAAAA
            // ----BBBB----
            return oldKSet.truncate(newBegin - oldBegin, newEnd - newBegin);
        }
        assert false : "Not Reachable";
        return null;
    }

    /**
     * Return the Entry at position where intersect `aLoc` in envMap,
     * return null if no intersection aLoc in envMap.
     * This is useful for tainting, avoid cutting up the ALoc frequently.
     *
     * @param aLoc the pointer ALoc
     * @return the Entry at position where intersect `aLoc`, or null if none found.
     */
    public Entry<ALoc, KSet> getOverlapEntry(ALoc aLoc) {
        Holder<Entry<ALoc, KSet>> holder = envMap.findEntry(aLoc);
        return holder.getValueOrNull();
    }

    private void writeEntry(StringBuilder sb, ALoc aLoc, KSet kSet) {
        sb.append(aLoc).append(" -> ").append(kSet).append("\n");
    }

    /**
     * Use for handling sub-register.
     * @param sb
     * @param aLoc
     * @param kSet
     */
    private void writeRegEntry(StringBuilder sb, ALoc aLoc, KSet kSet) {
        Register register = GlobalState.currentProgram.getLanguage()
                .getRegister(GlobalState.flatAPI.getAddressFactory().getRegisterSpace(), aLoc.getBegin(),
                        aLoc.getLen());
        if (register == null) {
            return;
        }
        if (!register.isBaseRegister()) {
            Register parentReg = register.getParentRegister();
            ALoc parentALoc = ALoc.getALoc(Reg.getInstance(), parentReg.getOffset(), parentReg.getNumBytes());
            KSet parentKSet = this.get(parentALoc);
            if (parentKSet.isBot()) {
                writeEntry(sb, aLoc, kSet);
            } else {
                sb.append(parentReg).append(" -> ").append(parentKSet).append("\n");
            }
        } else {
            writeEntry(sb, aLoc, kSet);
        }
    }

    @Override
    public String toString() {
        StringBuilder stringBuilder = new StringBuilder();
        for (Entry<ALoc, KSet> entry : envMap) {
            ALoc aLoc = entry.getKey();
            KSet kSet = entry.getValue();
            if (aLoc.getRegion().isReg()) {
                writeRegEntry(stringBuilder, aLoc, kSet);
            } else {
                writeEntry(stringBuilder, aLoc, kSet);
            }

        }
        return stringBuilder.toString();
    }

}

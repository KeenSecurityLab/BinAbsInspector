package com.bai.util;

import com.bai.env.ALoc;
import com.bai.env.AbsEnv;
import com.bai.env.AbsVal;
import com.bai.env.KSet;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DoubleDataType;
import ghidra.program.model.data.FloatDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongDataType;
import ghidra.program.model.data.LongDoubleDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.WideChar32DataType;
import ghidra.program.model.data.WideCharDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.util.string.FoundString;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.List;

import java.util.Objects;
import java.util.regex.MatchResult;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import org.apache.commons.lang3.ArrayUtils;
import org.javimmutable.collections.JImmutableMap.Entry;

/**
 * String utilities.
 */
public class StringUtils {

    private static final int DEFAULT_LEN = 0x10;
    public static final int MAX_LEN = 0x100;
    private static final Pattern FORMAT_PATTERN = Pattern.compile("%\\.?\\d*([lLh]{0,2}[cdieEfgGosuxXpn])");
    private static final String TMP_NAME = "tmpname";
    private static final DataType CHAR_PTR = PointerDataType.getPointer(CharDataType.dataType, -1);

    /**
     * Get string from an address with Ghidra API.
     * @param address the target address
     * @return the string, or null if no string found.
     */
    public static String getStringFromProgramData(Address address) {
        AddressSet addressSet = new AddressSet(address, address.add(MAX_LEN));
        List<FoundString> foundStringList = GlobalState.flatAPI.findStrings(addressSet, 2, 1, true, false);
        if (foundStringList == null || foundStringList.size() == 0) {
            return null;
        }
        return foundStringList.get(0).getString(GlobalState.currentProgram.getMemory());
    }

    /**
     * Convert AbsVal to a byte array
     *
     * @param strAbsVal the string AbsVal
     * @param bits the bit length of AbsVal, use for adding leading zeros
     * @return byte[]
     */
    public static byte[] getByteArray(AbsVal strAbsVal, int bits) {
        byte[] res = strAbsVal.toBigInteger(bits, false).setBit(bits).toByteArray();
        res = Arrays.copyOfRange(res, 1, res.length); // remove sign bit
        if (GlobalState.arch.isLittleEndian()) {
            ArrayUtils.reverse(res);
        }
        return res;
    }

    /**
     * Get the length of string from pointer.
     *
     * @param ptrAbsVal the pointer AbsVal
     * @param absEnv the AbsEnv
     * @return return DEFAULT_LEN if ptrAbsVal is invalid or not point to singleton, otherwise return the length.
     */
    public static int strlen(AbsVal ptrAbsVal, AbsEnv absEnv) {
        int offset = 0;
        if (ptrAbsVal.isBigVal()) {
            return DEFAULT_LEN;
        }
        ALoc ptrALoc = ALoc.getALoc(ptrAbsVal.getRegion(), ptrAbsVal.getValue(), 1);
        if (ptrALoc.isGlobalReadable()) {
            String str = getStringFromProgramData(GlobalState.flatAPI.toAddr(ptrAbsVal.getValue()));
            return str == null ? 0 : str.length();
        }

        while (true) {
            Entry<ALoc, KSet> entry = absEnv.getOverlapEntry(ptrALoc);
            if (entry == null) {
                break;
            }
            ALoc strALoc = entry.getKey();
            KSet strKSet = entry.getValue();
            if (!strKSet.isNormal() || !strKSet.isSingleton()) { // only consider singleton string.
                return DEFAULT_LEN;
            }
            AbsVal strAbsVal = strKSet.iterator().next();
            byte[] strByteArray = getByteArray(strAbsVal, strKSet.getBits());
            int idx = ArrayUtils.indexOf(strByteArray, (byte) 0);
            if (idx != -1) {
                offset += idx;
                break;
            }
            offset += strALoc.getLen();
            ptrALoc = ALoc.getALoc(ptrAbsVal.getRegion(), ptrAbsVal.getValue() + offset, 1);
        }

        if (offset != 0) {
            return offset;
        } else {
            if (ptrALoc.isGlobalReadable()) {
                String str = getStringFromProgramData(GlobalState.flatAPI.toAddr(ptrAbsVal.getValue()));
                return str == null ? 0 : str.length();
            }
            return 0;
        }
    }

    /**
     * Find first character index from string pointer
     *
     * @param ptrAbsVal the pointer AbsVal
     * @param c the character to find
     * @param absEnv the AbsEnv
     * @return return the index of first found character, -1 if not found.
     */
    public static int indexOf(AbsVal ptrAbsVal, char c, AbsEnv absEnv) {
        String str = getString(ptrAbsVal, absEnv);
        return str == null ? -1 : str.indexOf(c);
    }

    /**
     * Get String from a pointer, only works for String made up of singleton KSets.
     *
     * @param ptrAbsVal the pointer AbsVal
     * @param absEnv the AbsEnv
     * @return the String , or null if not found or encounter non-singleton KSet.
     */
    public static String getString(AbsVal ptrAbsVal, AbsEnv absEnv) {
        String res = null;
        if (ptrAbsVal.isBigVal()) {
            return res;
        }
        ALoc ptrALoc = ALoc.getALoc(ptrAbsVal.getRegion(), ptrAbsVal.getValue(), 1);
        if (ptrALoc.isGlobalReadable()) {
            return getStringFromProgramData(GlobalState.flatAPI.toAddr(ptrAbsVal.getValue()));
        }
        int offset = 0;
        byte[] resByteArray = null;
        while (true) {
            Entry<ALoc, KSet> entry = absEnv.getOverlapEntry(ptrALoc);
            if (entry == null) {
                break;
            }
            KSet strKSet = entry.getValue();
            if (!strKSet.isNormal() || !strKSet.isSingleton()) {
                break;
            }
            AbsVal strAbsVal = strKSet.iterator().next();
            byte[] strByteArray = getByteArray(strAbsVal, strKSet.getBits());
            int idx = ArrayUtils.indexOf(strByteArray, (byte) 0);
            if (idx != -1) {
                strByteArray = ArrayUtils.subarray(strByteArray, 0, idx);
                resByteArray = ArrayUtils.addAll(resByteArray, strByteArray);
                break;
            }
            resByteArray = ArrayUtils.addAll(resByteArray, strByteArray);
            ALoc strALoc = entry.getKey();
            offset += strALoc.getLen();
            ptrALoc = ALoc.getALoc(ptrAbsVal.getRegion(), ptrAbsVal.getValue() + offset, 1);

        }
        if (resByteArray != null) {
            return new String(resByteArray);
        } else {
            if (!ptrALoc.isGlobalReadable()) {
                return null;
            }
            return getStringFromProgramData(GlobalState.flatAPI.toAddr(ptrAbsVal.getValue()));
        }
    }

    /**
     * Copy a string of size from src to dst
     *
     * @param dstAbsVal the dst pointer AbsVal
     * @param srcAbsVal the src pointer AbsVal
     * @param absEnv the AbsEnv
     * @param size the size to copy from src to dst
     * @return return true if success
     */
    public static boolean copyString(AbsVal dstAbsVal, AbsVal srcAbsVal, AbsEnv absEnv, int size) {
        int offset = 0;
        ALoc ptrALoc = ALoc.getALoc(srcAbsVal.getRegion(), srcAbsVal.getValue(), 1);
        while (true) {
            Entry<ALoc, KSet> entry = absEnv.getOverlapEntry(ptrALoc);
            if (entry == null) {
                break;
            }
            KSet srcStrKSet = entry.getValue();
            if (!srcStrKSet.isNormal() || !srcStrKSet.iterator().hasNext()) {
                break;
            }
            if (!srcStrKSet.isSingleton()) { // only consider singleton string.
                break;
            }
            AbsVal strAbsVal = srcStrKSet.iterator().next();
            byte[] strByteArray = StringUtils.getByteArray(strAbsVal, srcStrKSet.getBits());
            int idx = ArrayUtils.indexOf(strByteArray, (byte) 0);
            int nowStrLen = (idx == -1 ? strByteArray.length : idx + 1);
            if (offset + nowStrLen > size) {
                idx = size - offset;
            }
            if (idx != -1) {
                byte[] bytes = Arrays.copyOf(strByteArray, ++idx);
                bytes[idx - 1] = 0;
                if (GlobalState.arch.isLittleEndian()) {
                    ArrayUtils.reverse(bytes);
                }
                KSet kSet = new KSet(idx * 8);
                if (idx > 8) {
                    kSet = kSet.insert(new AbsVal(new BigInteger(bytes)));
                } else {
                    kSet = kSet.insert(new AbsVal(new BigInteger(bytes).longValue()));
                }
                ALoc dstALoc = ALoc.getALoc(dstAbsVal.getRegion(), dstAbsVal.getValue() + offset, idx);
                absEnv.set(dstALoc, kSet, true);
                return true;
            }
            ALoc srcStrALoc = entry.getKey();
            ALoc dstALoc = ALoc.getALoc(dstAbsVal.getRegion(), dstAbsVal.getValue() + offset, srcStrALoc.getLen());
            absEnv.set(dstALoc, srcStrKSet, true);
            offset += srcStrALoc.getLen();
            ptrALoc = ALoc.getALoc(srcAbsVal.getRegion(), srcAbsVal.getValue() + offset, 1);
        }

        if (ptrALoc.isGlobalReadable()) {
            String str = StringUtils.getStringFromProgramData(GlobalState.flatAPI.toAddr(srcAbsVal.getValue()));
            if (str == null) {
                return false;
            }
            byte[] tmp = str.getBytes();
            byte[] bytes = new byte[Math.min(str.length(), size) + 1];
            System.arraycopy(tmp, 0, bytes, 0, Math.min(str.length(), size));
            if (GlobalState.arch.isLittleEndian()) {
                ArrayUtils.reverse(bytes);
            }
            KSet kSet = new KSet(bytes.length * 8);
            AbsVal absVal;
            if (bytes.length > 8) {
                absVal = new AbsVal(new BigInteger(bytes));
            } else {
                absVal = new AbsVal(new BigInteger(bytes).longValue());
            }
            ALoc dstALoc = ALoc.getALoc(dstAbsVal.getRegion(), dstAbsVal.getValue(), bytes.length);
            absEnv.set(dstALoc, kSet.insert(absVal), true);
            return true;
        }
        return false;
    }

    private static DataType toDataType(CharSequence match) {
        if (match.charAt(0) == 'h' && match.charAt(1) == 'h') {
            switch (match.charAt(2)) {
                case 'i':
                case 'd':
                case 'o':
                    return CharDataType.dataType;
                case 'u':
                case 'x':
                case 'X':
                    return UnsignedCharDataType.dataType;
                default: // fall to return null
            }
        } else if (match.charAt(0) == 'l' && match.charAt(1) == 'l') {
            switch (match.charAt(2)) {
                case 'c':
                    return WideChar32DataType.dataType;
                case 's':
                    return PointerDataType.getPointer(WideChar32DataType.dataType, -1);
                case 'i':
                case 'd':
                case 'o':
                    return LongLongDataType.dataType;
                case 'u':
                case 'x':
                case 'X':
                    return UnsignedLongLongDataType.dataType;
                case 'e':
                case 'E':
                case 'f':
                case 'g':
                case 'G':
                    return LongDoubleDataType.dataType;
                default: // fall to return null
            }
        } else if (match.charAt(0) == 'h') {
            switch (match.charAt(1)) {
                case 'i':
                case 'd':
                case 'o':
                    return ShortDataType.dataType;
                case 'u':
                case 'x':
                case 'X':
                    return UnsignedShortDataType.dataType;
                default: // fall to return null
            }
        } else if (match.charAt(0) == 'l') {
            switch (match.charAt(1)) {
                case 'c':
                    return WideCharDataType.dataType;
                case 's':
                    return PointerDataType.getPointer(WideCharDataType.dataType, -1);
                case 'i':
                case 'd':
                case 'o':
                    return LongDataType.dataType;
                case 'u':
                case 'x':
                case 'X':
                    return UnsignedLongDataType.dataType;
                case 'e':
                case 'E':
                case 'f':
                case 'g':
                case 'G':
                    return DoubleDataType.dataType;
                default: // fall to return null
            }
        } else if (match.charAt(0) == 'L') {
            switch (match.charAt(1)) {
                case 'e':
                case 'E':
                case 'f':
                case 'g':
                case 'G':
                    return LongDoubleDataType.dataType;
                default: // fall to return null
            }
        } else {
            switch (match.charAt(0)) {
                case 'c':
                    return CharDataType.dataType;
                case 's':
                    return PointerDataType.getPointer(CharDataType.dataType, -1);
                case 'i':
                case 'd':
                case 'o':
                    return IntegerDataType.dataType;
                case 'u':
                case 'x':
                case 'X':
                    return UnsignedIntegerDataType.dataType;
                case 'e':
                case 'E':
                case 'f':
                case 'g':
                case 'G':
                    return FloatDataType.dataType;
                case 'p':
                    return PointerDataType.dataType;
                default: // fall to return null
            }
        }
        Logging.debug("Unknown Specifier: " + match);
        return null;
    }

    private static String getSpecifier(MatchResult r) {
        return r.group(1);
    }

    private static ParameterDefinition toParameter(DataType dt) {
        return new ParameterDefinitionImpl(null, dt, null);
    }

    /**
     * Get a function signature according to given format string.
     * @param format the format string.
     * @param function the function.
     * @return the function signature.
     */
    public static FunctionDefinition getFunctionSignature(String format, Function function) {
        final FunctionDefinition def = new FunctionDefinitionDataType(TMP_NAME);
        final Matcher matcher = FORMAT_PATTERN.matcher(format);
        final Stream<ParameterDefinition> varParamStream = matcher.results()
                .map(StringUtils::getSpecifier)
                .map(StringUtils::toDataType)
                .filter(Objects::nonNull)
                .map(StringUtils::toParameter);

        ParameterDefinition[] p = Stream.concat(Arrays.stream(function.getSignature().getArguments()), varParamStream)
                .toArray(ParameterDefinition[]::new);
        def.setArguments(p);
        def.setReturnType(IntegerDataType.dataType);
        def.setVarArgs(true);
        return def;
    }
}

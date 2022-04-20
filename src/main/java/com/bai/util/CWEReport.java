package com.bai.util;

import com.bai.env.Context;
import com.google.errorprone.annotations.CheckReturnValue;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import java.util.Objects;
import org.apache.logging.log4j.message.Message;

/**
 * The report of a CWE warning.
 */
public class CWEReport implements Message {

    private String cwe;
    private String version;
    private String details;
    private Address address;
    private Context context;

    public CWEReport(String cwe, String version, String details) {
        this.cwe = cwe;
        this.version = version;
        this.details = details;
    }

    /**
     * Get the address which generates this report.
     * @return the address.
     */
    public Address getAddress() {
        return address;
    }

    /**
     * Get the cwe number.
     * @return the cwe number.
     */
    public String getCwe() {
        return cwe;
    }

    /**
     * Get the context.
     * @return the context.
     */
    public Context getContext() {
        return context;
    }

    /**
     * Set the address which generates this report.
     * @param address the address.
     * @return the cwe report.
     */
    @CheckReturnValue
    public CWEReport setAddress(Address address) {
        this.address = address;
        return this;
    }

    /**
     * Set the context of this report.
     * @param context the context.
     * @return the cwe report.
     */
    @CheckReturnValue
    public CWEReport setContext(Context context) {
        this.context = context;
        return this;
    }

    @Override
    public String toString() {
        return getFormattedMessage();
    }

    /**
     *  Get a formatted string
     * @return the formated string
     */
    @Override
    public String getFormattedMessage() {
        StringBuilder msgBuilder = new StringBuilder(cwe + ": " + details);
        if (address != null) {
            msgBuilder.append(" @ ").append(address);
        }
        if (context != null) {
            msgBuilder.append(" [ ");
            long[] callString = context.getCallString();
            Function[] functions = context.getFuncs();
            assert callString.length == functions.length;
            for (int i = functions.length - 1; i >= 0; i--) {
                if (functions[i] == null) {
                    continue;
                }
                msgBuilder.append(GlobalState.flatAPI.toAddr(callString[i]).toString());
                msgBuilder.append(" (");
                msgBuilder.append(functions[i].getSymbol().getName());
                msgBuilder.append(")");
                if (i >= 1 && functions[i - 1] != null) {
                    msgBuilder.append(", ");
                }
            }
            msgBuilder.append(" ]");
        }
        return msgBuilder.toString();
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public Object[] getParameters() {
        return new Object[0];
    }

    @Override
    public Throwable getThrowable() {
        return null;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof CWEReport)) {
            return false;
        }
        CWEReport otherReport = (CWEReport) o;
        return Objects.equals(cwe, otherReport.cwe)
                && Objects.equals(address, otherReport.address)
                && Objects.equals(context, otherReport.context);
    }

    @Override
    public int hashCode() {
        return Objects.hashCode(cwe) * 31 + Objects.hashCode(address) * 17 + Objects.hashCode(context);
    }
}

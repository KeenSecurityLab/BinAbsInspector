package com.bai.env.region;

import com.bai.env.ALoc;
import com.bai.util.GlobalState;

/**
 * Register region.
 */
public class Reg extends RegionBase {
    private Reg() {
        super(TYPE_REG, -1L);
    }

    /**
     * Get the singleton Register region
     */
    public static Reg getInstance() {
        return RegisterInternal.INSTANCE;
    }

    private static class RegisterInternal {
        private static final Reg INSTANCE = new Reg();
    }

    /**
     * @hidden
     */
    @Override
    public boolean equals(Object obj) {
        return obj == this;
    }

    /**
     * @hidden
     */
    @Override
    public int hashCode() {
        return TYPE_REG;
    }

    /**
     * @hidden
     * @deprecated Improper method design, to be changed.
     */
    public static ALoc getALoc(String registerName) {
        return ALoc.getALoc(Reg.getInstance(),
                GlobalState.currentProgram.getRegister(registerName).getOffset(),
                GlobalState.arch.getDefaultPointerSize());
    }
}

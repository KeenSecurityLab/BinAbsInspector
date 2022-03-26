package com.bai.env.region;

import com.bai.env.ALoc;
import com.bai.util.GlobalState;

public class Reg extends RegionBase {
    private Reg() {
        super(TYPE_REG, -1L);
    }

    public static Reg getInstance() {
        return RegisterInternal.INSTANCE;
    }

    private static class RegisterInternal {
        private static final Reg INSTANCE = new Reg();
    }

    @Override
    public boolean equals(Object obj) {
        return obj == this;
    }

    @Override
    public int hashCode() {
        return TYPE_REG;
    }

    public static ALoc getALoc(String registerName) {
        return ALoc.getALoc(Reg.getInstance(),
                GlobalState.currentProgram.getRegister(registerName).getOffset(),
                GlobalState.arch.getDefaultPointerSize());
    }
}

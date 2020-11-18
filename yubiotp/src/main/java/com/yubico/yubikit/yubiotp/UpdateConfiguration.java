package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.Version;

public class UpdateConfiguration extends KeyboardSlotConfiguration<UpdateConfiguration> {
    private static final byte TKTFLAG_UPDATE_MASK = TKTFLAG_TAB_FIRST | TKTFLAG_APPEND_TAB1 | TKTFLAG_APPEND_TAB2 | TKTFLAG_APPEND_DELAY1 | TKTFLAG_APPEND_DELAY2 | TKTFLAG_APPEND_CR;
    private static final byte CFGFLAG_UPDATE_MASK = CFGFLAG_PACING_10MS | CFGFLAG_PACING_20MS;

    @Override
    public boolean isSupportedBy(Version version) {
        return YubiOtpSession.FEATURE_UPDATE.supports(version) && super.isSupportedBy(version);
    }

    @Override
    protected UpdateConfiguration getThis() {
        return this;
    }

    @Override
    protected UpdateConfiguration updateTktFlags(byte bit, boolean value, Version minVersion) {
        if ((TKTFLAG_UPDATE_MASK & bit) == 0) {
            throw new IllegalArgumentException("Unsupported TKT flags for update");
        }
        return super.updateTktFlags(bit, value, minVersion);
    }

    @Override
    protected UpdateConfiguration updateCfgFlags(byte bit, boolean value, Version minVersion) {
        if ((CFGFLAG_UPDATE_MASK & bit) == 0) {
            throw new IllegalArgumentException("Unsupported CFG flags for update");
        }
        return super.updateCfgFlags(bit, value, minVersion);
    }

    // NB: All EXT flags are valid for update.

    /**
     * This setting cannot be changed for update, and this method will throw an IllegalArgumentException
     *
     * @param protectSlot2 If true, slot 2 cannot be modified.
     * @return this method will not return normally
     */
    @Override
    public UpdateConfiguration protectSlot2(boolean protectSlot2) {
        throw new IllegalArgumentException("protectSlot2 cannot be applied to UpdateConfiguration");
    }

    /**
     * Inserts tabs in-between different parts of the OTP.
     *
     * @param before      inserts a tab before any other output (default: false)
     * @param afterFirst  inserts a tab after the static part of the OTP (default: false)
     * @param afterSecond inserts a tab after the end of the OTP (default: false)
     * @return the configuration for chaining
     */
    public UpdateConfiguration tabs(boolean before, boolean afterFirst, boolean afterSecond) {
        updateTktFlags(TKTFLAG_TAB_FIRST, before, V1_0);
        updateTktFlags(TKTFLAG_APPEND_TAB1, afterFirst, V1_0);
        return updateTktFlags(TKTFLAG_APPEND_TAB2, afterSecond, V1_0);
    }

    /**
     * Inserts delays in-between different parts of the OTP.
     *
     * @param afterFirst  inserts a delay after the static part of the OTP (default: false)
     * @param afterSecond inserts a delay after the end of the OTP (default: false)
     * @return the configuration for chaining
     */
    public UpdateConfiguration delay(boolean afterFirst, boolean afterSecond) {
        updateTktFlags(TKTFLAG_APPEND_DELAY1, afterFirst, V1_0);
        return updateTktFlags(TKTFLAG_APPEND_DELAY2, afterSecond, V1_0);
    }
}

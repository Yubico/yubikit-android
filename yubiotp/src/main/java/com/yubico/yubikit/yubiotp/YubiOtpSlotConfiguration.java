package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.Version;

import java.util.Arrays;

/**
 * Configures the YubiKey to return YubiOTP (one-time password) on touch.
 */
public class YubiOtpSlotConfiguration extends KeyboardSlotConfiguration<YubiOtpSlotConfiguration> {
    /**
     * Creates a Yubico OTP configuration with default settings.
     *
     * @param publicId  public id (0-16 bytes)
     * @param privateId private id (6 bytes)
     * @param key       the secret key to store on YubiKey (20 bytes)
     */
    public YubiOtpSlotConfiguration(byte[] publicId, byte[] privateId, byte[] key) {
        super(new Version(0, 0, 0));

        if (publicId.length > ConfigUtils.FIXED_SIZE) {
            throw new IllegalArgumentException("Public ID must be <= 16 bytes");
        }

        fixed = Arrays.copyOf(publicId, publicId.length);
        System.arraycopy(privateId, 0, uid, 0, privateId.length);
        System.arraycopy(key, 0, this.key, 0, key.length);
    }

    @Override
    protected YubiOtpSlotConfiguration getThis() {
        return this;
    }

    /**
     * Inserts tabs in-between different parts of the OTP.
     *
     * @param before      inserts a tab before any other output (default: false)
     * @param afterFirst  inserts a tab after the static part of the OTP (default: false)
     * @param afterSecond inserts a tab after the end of the OTP (default: false)
     * @return the configuration for chaining
     */
    public YubiOtpSlotConfiguration tabs(boolean before, boolean afterFirst, boolean afterSecond) {
        updateTktFlags(TKTFLAG_TAB_FIRST, before);
        updateTktFlags(TKTFLAG_APPEND_TAB1, afterFirst);
        return updateTktFlags(TKTFLAG_APPEND_TAB2, afterSecond);
    }

    /**
     * Inserts delays in-between different parts of the OTP.
     *
     * @param afterFirst  inserts a delay after the static part of the OTP (default: false)
     * @param afterSecond inserts a delay after the end of the OTP (default: false)
     * @return the configuration for chaining
     */
    public YubiOtpSlotConfiguration delay(boolean afterFirst, boolean afterSecond) {
        updateTktFlags(TKTFLAG_APPEND_DELAY1, afterFirst);
        return updateTktFlags(TKTFLAG_APPEND_DELAY2, afterSecond);
    }

    /**
     * Send a reference string of all 16 modhex characters before the OTP.
     *
     * @param sendReference if true, sends the reference string (default: false)
     * @return the configuration for chaining
     */
    public YubiOtpSlotConfiguration sendReference(boolean sendReference) {
        return updateCfgFlags(CFGFLAG_SEND_REF, sendReference);
    }
}

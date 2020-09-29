package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.NotSupportedOperation;
import com.yubico.yubikit.core.Version;

import java.nio.ByteBuffer;

/**
 * Configures YubiKey to return static password on touch.
 */
public class StaticPasswordSlotConfiguration extends KeyboardSlotConfiguration<StaticPasswordSlotConfiguration> {
    private static final int SCAN_CODES_SIZE = ConfigUtils.FIXED_SIZE + ConfigUtils.UID_SIZE + ConfigUtils.KEY_SIZE;

    /**
     * Creates a Static Password configuration with default settings.
     *
     * @param scanCodes the password to store on YubiKey as an array of keyboard scan codes.
     */
    public StaticPasswordSlotConfiguration(byte[] scanCodes) {
        super(new Version(2, 2, 0));

        if (scanCodes.length > SCAN_CODES_SIZE) {
            throw new NotSupportedOperation("Password is too long");
        }

        // Scan codes are packed into fixed, uid, and key, and zero padded.
        fixed = new byte[ConfigUtils.FIXED_SIZE];
        ByteBuffer.allocate(SCAN_CODES_SIZE).put(scanCodes).rewind().get(fixed).get(uid).get(key);

        updateCfgFlags(CFGFLAG_SHORT_TICKET, true);
    }

    @Override
    protected StaticPasswordSlotConfiguration getThis() {
        return this;
    }
}

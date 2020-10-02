/*
 * Copyright (C) 2020 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.otp.ChecksumUtils;

import javax.annotation.Nullable;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

abstract class BaseSlotConfiguration<T extends BaseSlotConfiguration<T>> implements SlotConfiguration {
    // Config structure
    protected static final int FIXED_SIZE = 16;       // Max size of fixed field
    protected static final int UID_SIZE = 6;          // Size of secret ID field
    protected static final int KEY_SIZE = 16;         // Size of AES key

    private static final int ACC_CODE_SIZE = 6;     // Size of access code to re-program device
    private static final int CONFIG_SIZE = 52;      // Size of config struct (excluding current access code)

    protected byte[] fixed = new byte[0];
    protected final byte[] uid = new byte[UID_SIZE];
    protected final byte[] key = new byte[KEY_SIZE];

    private byte tkt = 0;
    private byte cfg = 0;
    private byte ext = EXTFLAG_SERIAL_API_VISIBLE | EXTFLAG_ALLOW_UPDATE;

    protected abstract T getThis();

    private byte updateFlags(byte flags, byte bit, boolean value) {
        if (value) {
            return (byte) (flags | bit);
        } else {
            return (byte) (flags & ~bit);
        }
    }

    protected final byte getTkt() {
        return tkt;
    }

    protected final byte getCfg() {
        return cfg;
    }

    protected final byte getExt() {
        return ext;
    }

    protected T updateTktFlags(byte bit, boolean value) {
        tkt = updateFlags(tkt, bit, value);
        return getThis();
    }

    protected T updateCfgFlags(byte bit, boolean value) {
        cfg = updateFlags(cfg, bit, value);
        return getThis();
    }

    protected T updateExtFlags(byte bit, boolean value) {
        ext = updateFlags(ext, bit, value);
        return getThis();
    }

    @Override
    public boolean isSupportedBy(Version version) {
        return true;
    }

    @Override
    public byte[] getConfig(@Nullable byte[] accCode) {
        return buildConfig(fixed, uid, key, ext, tkt, cfg, accCode);
    }

    public T serialApiVisible(boolean serialApiVisible) {
        return updateExtFlags(EXTFLAG_SERIAL_API_VISIBLE, serialApiVisible);
    }

    public T serialUsbVisible(boolean serialUsbVisible) {
        return updateExtFlags(EXTFLAG_SERIAL_USB_VISIBLE, serialUsbVisible);
    }

    public T allowUpdate(boolean allowUpdate) {
        return updateExtFlags(EXTFLAG_ALLOW_UPDATE, allowUpdate);
    }

    /**
     * Makes the configuration dormant (hidden from use). A dormant configuration needs to be updated and the dormant
     * bit removed to be used.
     *
     * @param dormant if true, the configuration cannot be used
     * @return the configuration for chaining
     */
    public T dormant(boolean dormant) {
        return updateExtFlags(EXTFLAG_DORMANT, dormant);
    }

    /**
     * Inverts the behaviour of the led on the YubiKey.
     *
     * @param invertLed if true, the LED behavior is inverted
     * @return the configuration for chaining
     */
    public T invertLed(boolean invertLed) {
        return updateExtFlags(EXTFLAG_LED_INV, invertLed);
    }

    /**
     * When set for slot 1, access to modify slot 2 is blocked (even if slot 2 is empty).
     *
     * @param protectSlot2 If true, slot 2 cannot be modified.
     * @return the configuration for chaining
     */
    public T protectSlot2(boolean protectSlot2) {
        return updateTktFlags(TKTFLAG_PROTECT_CFG2, protectSlot2);
    }

    static byte[] buildConfig(byte[] fixed, byte[] uid, byte[] key, byte extFlags, byte tktFlags, byte cfgFlags, @Nullable byte[] accCode) {
        if (fixed.length > FIXED_SIZE) {
            throw new IllegalArgumentException("Incorrect length for fixed");
        }
        if (uid.length != UID_SIZE) {
            throw new IllegalArgumentException("Incorrect length for uid");
        }
        if (key.length != KEY_SIZE) {
            throw new IllegalArgumentException("Incorrect length for key");
        }
        if (accCode != null && accCode.length != ACC_CODE_SIZE) {
            throw new IllegalArgumentException("Incorrect length for access code");
        }

        ByteBuffer config = ByteBuffer.allocate(CONFIG_SIZE).order(ByteOrder.LITTLE_ENDIAN);
        return config.put(Arrays.copyOf(fixed, FIXED_SIZE))
                .put(uid)
                .put(key)
                .put(accCode == null ? new byte[ACC_CODE_SIZE] : accCode)
                .put((byte) fixed.length)
                .put(extFlags)
                .put(tktFlags)
                .put(cfgFlags)
                .putShort((short) 0) // 2 bytes RFU
                .putShort((short) ~ChecksumUtils.calculateCrc(config.array(), config.position()))
                .array();
    }
}

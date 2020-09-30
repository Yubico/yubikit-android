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

import javax.annotation.Nullable;

abstract class BaseSlotConfiguration<T extends BaseSlotConfiguration<T>> implements SlotConfiguration {
    private final Version minVersion;

    protected byte[] fixed = new byte[0];
    protected final byte[] uid = new byte[ConfigUtils.UID_SIZE];
    protected final byte[] key = new byte[ConfigUtils.KEY_SIZE];

    private byte tkt = 0;
    private byte cfg = 0;
    private byte ext = EXTFLAG_SERIAL_API_VISIBLE | EXTFLAG_ALLOW_UPDATE;

    protected BaseSlotConfiguration(Version minVersion) {
        this.minVersion = minVersion;
    }

    protected abstract T getThis();

    private byte updateFlags(byte flags, byte bit, boolean value) {
        if (value) {
            return (byte) (flags | bit);
        } else {
            return (byte) (flags & ~bit);
        }
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
    public Version getMinimumVersion() {
        return minVersion;
    }

    @Override
    public byte[] getConfig(@Nullable byte[] accCode) {
        return ConfigUtils.buildConfig(fixed, uid, key, ext, tkt, cfg, accCode);
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
}

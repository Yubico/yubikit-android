/*
 * Copyright (C) 2019 Yubico.
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

/**
 * Data object containing the state of slot programming for a YubiKey.
 */
public class ConfigState {
    private static final byte CONFIG1_VALID = 0x01;        /* Bit in touchLevel indicating that configuration 1 is valid (from firmware 2.1) */
    private static final byte CONFIG2_VALID = 0x02;        /* Bit in touchLevel indicating that configuration 2 is valid (from firmware 2.1) */
    private static final byte CONFIG1_TOUCH = 0x04;       /* Bit in touchLevel indicating that configuration 1 requires touch (from firmware 3.0) */
    private static final byte CONFIG2_TOUCH = 0x08;       /* Bit in touchLevel indicating that configuration 2 requires touch (from firmware 3.0) */
    private static final byte CONFIG_LED_INV = 0x10;       /* Bit in touchLevel indicating that LED behavior is inverted (EXTFLAG_LED_INV mirror) */
    private static final byte CONFIG_STATUS_MASK = 0x1f;        /* Mask for status bits */

    private final Version version;
    private final byte flags;

    ConfigState(Version version, short touchLevel) {
        this.version = version;
        this.flags = (byte) (CONFIG_STATUS_MASK & touchLevel);
    }

    /**
     * Checks if a slot is configured or empty
     * <p>
     * This functionality requires support for {@link YubiOtp#FEATURE_CHECK_CONFIGURED}, available on YubiKey 2.1 or later.
     *
     * @param slot the slot to check
     * @return true if the slot holds configuration, false if empty
     */
    public boolean slotIsConfigured(Slot slot) {
        if (YubiOtp.FEATURE_CHECK_CONFIGURED.isSupportedBy(version)) {
            return (flags & slot.map(CONFIG1_VALID, CONFIG2_VALID)) != 0;
        }
        throw new UnsupportedOperationException("Checking if a slot is configured is not supported on this YubiKey.");
    }

    /**
     * Checks if a configured slot requires touch or not.
     * <p>
     * This functionality requires support for {@link YubiOtp#FEATURE_CHECK_TOUCH}, available on YubiKey 3.0 or later.
     *
     * @param slot the slot to check
     * @return true of the slot requires touch, false if not (or if checking isn't supported)
     */
    public boolean slotRequiresTouch(Slot slot) {
        if (YubiOtp.FEATURE_CHECK_TOUCH.isSupportedBy(version)) {
            return (flags & slot.map(CONFIG1_TOUCH, CONFIG2_TOUCH)) != 0;
        }
        throw new UnsupportedOperationException("Checking if a slot requires touch is not supported on this YubiKey.");
    }

    /**
     * Checks if the LED has been configured to be inverted.
     *
     * @return true if inverted, false if not
     */
    public boolean isLedInverted() {
        return YubiOtp.FEATURE_INVERT_LED.isSupportedBy(version) && (flags & CONFIG_LED_INV) != 0;
    }
}

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

package com.yubico.yubikit.otp;

import com.yubico.yubikit.apdu.Version;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class Status {

    private static short CONFIG1_VALID = 0x01;        /* Bit in touchLevel indicating that configuration 1 is valid (from firmware 2.1) */
    private static short CONFIG2_VALID = 0x02;        /* Bit in touchLevel indicating that configuration 2 is valid (from firmware 2.1) */
    private static short CONFIG1_TOUCH = 0x04;       /* Bit in touchLevel indicating that configuration 1 requires touch (from firmware 3.0) */
    private static short CONFIG2_TOUCH = 0x08;       /* Bit in touchLevel indicating that configuration 2 requires touch (from firmware 3.0) */
    private static short CONFIG_LED_INV = 0x10;       /* Bit in touchLevel indicating that LED behavior is inverted (EXTFLAG_LED_INV mirror) */
    private static short CONFIG_STATUS_MASK = 0x1f;        /* Mask for status bits */

    /**
     * Firmware version
     */
    private Version version;

    private byte pgmSeq;        /* Programming sequence number. 0 if no valid configuration */
    private short touchLevel;    /* Level from touch detector */

    Status(Version version, byte sequence, short touchLevel) {
        this.version = version;
        this.pgmSeq = sequence;
        this.touchLevel = touchLevel;
    }

    public boolean isSlotConfigured(Slot slot) {
        return (touchLevel & slot.map(CONFIG1_VALID, CONFIG2_VALID)) != 0;
    }

    public boolean isSlotTouch(Slot slot) {
        return version.isAtLeast(3, 0, 0) && (touchLevel & slot.map(CONFIG1_TOUCH, CONFIG2_TOUCH)) != 0;
    }

    public boolean isLedInverted() {
        return (touchLevel & CONFIG_LED_INV) != 0;
    }

    /**
     * Parse status response returned by YubiKey (select OTP applet)
     *
     * @param bytes data from YubiKey
     * @return status object that contains firmware version
     */
    static Status parse(byte[] bytes) {
        ByteBuffer data = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);
        Version version = new Version(data.get(), data.get(), data.get());
        if (data.remaining() < 3) {
            return new Status(version, (byte) 0, (short) 0);
        }
        return new Status(version, data.get(), data.getShort());
    }

    Version getVersion() {
        return version;
    }

    byte getProgrammingSequence() {
        return pgmSeq;
    }
}

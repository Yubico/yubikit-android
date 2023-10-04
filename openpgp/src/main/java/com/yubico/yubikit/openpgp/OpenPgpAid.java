/*
 * Copyright (C) 2023 Yubico.
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

package com.yubico.yubikit.openpgp;

import static com.yubico.yubikit.openpgp.OpenPgpUtils.decodeBcd;

import com.yubico.yubikit.core.util.Pair;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * OpenPGP Application Identifier (AID)
 * The OpenPGP AID is a string of bytes identifying the OpenPGP application.
 * It also embeds some values which are accessible though properties.
 */
public class OpenPgpAid {
    private final byte[] bytes;

    OpenPgpAid(byte[] bytes) {
        this.bytes = bytes;
    }

    public byte[] getBytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }

    /**
     * OpenPGP version (tuple of 2 integers: main version, secondary version).
     *
     * @return a Pair of main version, secondary version.
     */
    public Pair<Byte, Byte> getVersion() {
        return new Pair<>(decodeBcd(bytes[6]), decodeBcd(bytes[7]));
    }

    /**
     * 16-bit integer value identifying the manufacturer of the device.
     * This should be 6 for Yubico devices.
     *
     * @return OpenPGP card manufacturer ID.
     */
    public short getManufacturer() {
        return ByteBuffer.wrap(bytes).getShort(6);
    }

    /**
     * The serial number of the YubiKey.
     * <p>
     * NOTE: This value is encoded in BCD. In the event of an invalid value (hex A-F)
     * the entire 4 byte value will instead be decoded as an unsigned integer,
     * and negated.
     *
     * @return The serial number of the YubiKey
     */
    public int getSerial() {
        int serial = 0;
        try {
            for (int i = 0; i < 4; i++) {
                serial = serial * 100 + decodeBcd(bytes[10 + i]);
            }
            return serial;
        } catch (IllegalArgumentException e) {
            return -ByteBuffer.wrap(bytes).getInt(10);
        }
    }
}

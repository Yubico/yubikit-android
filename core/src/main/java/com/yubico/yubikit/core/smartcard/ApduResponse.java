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

package com.yubico.yubikit.core.smartcard;

import java.util.Arrays;

/**
 * An APDU response from a YubiKey, comprising response data, and a status code.
 */
public class ApduResponse {
    private final byte[] bytes;

    /**
     * Creates a new response from a key
     *
     * @param bytes data received from key within session/service provider
     */
    public ApduResponse(byte[] bytes) {
        if (bytes.length < 2) {
            throw new IllegalArgumentException("Invalid APDU response data");
        }
        this.bytes = Arrays.copyOf(bytes, bytes.length);
    }

    /**
     * @return the SW from a key response (see {@link SW}).
     */
    public short getSw() {
        return (short) (((0xff & bytes[bytes.length - 2]) << 8) | (0xff & bytes[bytes.length - 1]));
    }

    /**
     * @return the data from a key response without the SW.
     */
    public byte[] getData() {
        return Arrays.copyOfRange(bytes, 0, bytes.length - 2);
    }

    /**
     * @return raw data from a key response
     */
    public byte[] getBytes() {
        return Arrays.copyOf(bytes, bytes.length);
    }
}

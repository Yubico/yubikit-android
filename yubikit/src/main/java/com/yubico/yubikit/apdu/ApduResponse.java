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

package com.yubico.yubikit.apdu;

import java.util.Arrays;

/**
 * Parses response to APDU from a key
 */
public class ApduResponse {
    private byte[] data;
    private int size;

    /**
     * Creates a new response from a key
     * @param data data received from key within session/service provider
     */
    public ApduResponse(byte[] data) {
        this.data = data;
        size = data != null ? data.length : 0;
    }

    /**
     * @return the SW from a key response.
     */
    public short statusCode() {
        if (size < 2) {
            return 0x00;
        }
        return (short)(((0xff & data[size-2]) << 8) | (0xff & data[size-1]));
    }

    /**
     * @return the data from a key response without the SW.
     */
    public byte[] responseData() {
        if (size < 3) {
            return null;
        }
        return Arrays.copyOfRange(this.data, 0, size - 2);
    }

    /**
     * @return raw data from a key response
     */
    public byte[] getData() {
        return data;
    }

    /**
     * Verifies that first byte of received status code equal to
     * @param status expected status code
     * @return true if first byte of status code equal to expected status code
     */
    public boolean hasStatusCode(byte status) {
        return statusCode() >> 8 == status;
    }

    /**
     * Verifies that received status code equal to
     * @param status expected status code
     * @return true if received status code equal to expected status code
     */
    public boolean hasStatusCode(short status) {
        return statusCode() == status;
    }
}

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

/**
 * Exception is thrown if used APDU utils to parse received data and it has unexpected status code (not equal success == 0x9000)
 */
public class ApduCodeException extends ApduException {
    static final long serialVersionUID = 1L;

    private int statusCode;

    public ApduCodeException(int statusCode) {
        super("Unexpected response received from the key");
        this.statusCode = statusCode;
    }

    /**
     * Gets error code that received via APDU response
     * @return error code
     */
    public int getStatusCode() {
        return statusCode;
    }
}

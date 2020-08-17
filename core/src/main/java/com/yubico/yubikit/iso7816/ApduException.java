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

package com.yubico.yubikit.iso7816;

import com.yubico.yubikit.exceptions.YubiKeyCommunicationException;
import com.yubico.yubikit.iso7816.ApduResponse;

import java.util.Locale;

/**
 * Exception is thrown if used APDU utils to parse received data and it has unexpected status code (not equal success == 0x9000)
 */
public class ApduException extends YubiKeyCommunicationException {
    static final long serialVersionUID = 1L;

    private ApduResponse apdu;

    public ApduException(ApduResponse apdu) {
        this(apdu, String.format(Locale.ROOT, "APDU error: 0x%04x", apdu.getSw()));
    }

    public ApduException(ApduResponse apdu, String message) {
        super(message);
        this.apdu = apdu;
    }

    /**
     * Gets error code that received via APDU response
     * @return error code
     */
    public short getStatusCode() {
        return apdu.getSw();
    }

    /**
     * Get the ResponseApdu.
     * @return the response APDU that generated the error
     */
    public ApduResponse getApdu() {
        return apdu;
    }
}

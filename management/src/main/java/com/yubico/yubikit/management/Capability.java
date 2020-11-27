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
package com.yubico.yubikit.management;

/**
 * Identifies a feature (typically an application) on a YubiKey which may or may not be supported, and which can be enabled or disabled.
 */
public enum Capability {
    /**
     * Identifies the YubiOTP application.
     */
    OTP(0x0001),
    /**
     * Identifies the U2F (CTAP1) portion of the FIDO application.
     */
    U2F(0x0002),
    /**
     * Identifies the OpenPGP application, implementing the OpenPGP Card protocol.
     */
    OPENPGP(0x0008),
    /**
     * Identifies the PIV application, implementing the PIV protocol.
     */
    PIV(0x0010),
    /**
     * Identifies the OATH application, implementing the YKOATH protocol.
     */
    OATH(0x0020),
    /**
     * Identifies the FIDO2 (CTAP2) portion of the FIDO application.
     */
    FIDO2(0x0200);

    public final int bit;

    Capability(int bit) {
        this.bit = bit;
    }
}

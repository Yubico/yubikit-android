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

package com.yubico.yubikit.management;

/**
 * Capabilities/Applications that supported by YubiKey
 */
public enum ApplicationType {
    UNKNOWN(0x00),
    OTP(0x01),
    U2F(0x02),
    CCID(0x04),
    OPGP(0x08),
    PIV(0x10),
    OATH(0x20),
    CTAP2(0x0200);

    public final short value;

    ApplicationType(int value) {
        this.value = (short)value;
    }

    public static ApplicationType valueOf(int appType) {
        return ApplicationType.values()[appType];
    }
}

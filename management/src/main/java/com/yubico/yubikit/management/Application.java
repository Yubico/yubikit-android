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

public enum Application {
    OTP(0x0001),
    U2F(0x0002),
    OPENPGP(0x0008),
    PIV(0x0010),
    OATH(0x0020),
    FIDO2(0x0200);

    public final int bit;

    Application(int bit) {
        this.bit = bit;
    }
}

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
 * Form factor is set during manufacturing and returned as a one-Byte value
 */
public enum FormFactor {
    UNKNOWN(0x00),
    USB_A_KEYCHAIN(0x01),
    USB_A_NANO(0x02),
    USB_C_KEYCHAIN(0x03),
    USB_C_NANO(0x04),
    USB_C_LIGHTNING(0x05);

    public final byte value;

    FormFactor(int value) {
        this.value = (byte)value;
    }

    public static FormFactor valueOf(byte formFactor) {
        if (formFactor > FormFactor.values().length) {
            return UNKNOWN;
        }
        return FormFactor.values()[formFactor];
    }
    public static FormFactor valueOf(byte[] formFactor) {
        if (formFactor == null || formFactor.length == 0) {
            return UNKNOWN;
        }
        return valueOf(formFactor[0]);
    }
}

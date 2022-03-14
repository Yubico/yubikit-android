/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.core;

public enum UsbPid {
    YKS_OTP(0x0010, YubiKeyType.YKS, UsbInterface.OTP),
    NEO_OTP(0x0110, YubiKeyType.NEO, UsbInterface.OTP),
    NEO_OTP_CCID(0x0111, YubiKeyType.NEO, UsbInterface.OTP | UsbInterface.CCID),
    NEO_CCID(0x0112, YubiKeyType.NEO, UsbInterface.CCID),
    NEO_FIDO(0x0113, YubiKeyType.NEO, UsbInterface.FIDO),
    NEO_OTP_FIDO(0x0114, YubiKeyType.NEO, UsbInterface.OTP | UsbInterface.FIDO),
    NEO_FIDO_CCID(0x0115, YubiKeyType.NEO, UsbInterface.CCID | UsbInterface.FIDO),
    NEO_OTP_FIDO_CCID(0x0116, YubiKeyType.NEO, UsbInterface.OTP | UsbInterface.FIDO | UsbInterface.CCID),
    SKY_FIDO(0x0120, YubiKeyType.SKY, UsbInterface.FIDO),
    YK4_OTP(0x0401, YubiKeyType.YK4, UsbInterface.OTP),
    YK4_FIDO(0x0402, YubiKeyType.YK4, UsbInterface.FIDO),
    YK4_OTP_FIDO(0x0403, YubiKeyType.YK4, UsbInterface.OTP | UsbInterface.FIDO),
    YK4_CCID(0x0404, YubiKeyType.YK4, UsbInterface.CCID),
    YK4_OTP_CCID(0x0405, YubiKeyType.YK4, UsbInterface.OTP | UsbInterface.CCID),
    YK4_FIDO_CCID(0x0406, YubiKeyType.YK4, UsbInterface.FIDO | UsbInterface.CCID),
    YK4_OTP_FIDO_CCID(0x0407, YubiKeyType.YK4, UsbInterface.OTP | UsbInterface.FIDO | UsbInterface.CCID),
    YKP_OTP_FIDO(0x0410, YubiKeyType.YKP, UsbInterface.OTP | UsbInterface.FIDO);

    public final int value;
    public final YubiKeyType type;
    public final int usbInterfaces;

    UsbPid(int value, YubiKeyType type, int usbInterfaces) {
        this.value = value;
        this.type = type;
        this.usbInterfaces = usbInterfaces;
    }

    static public UsbPid fromValue(int value) throws IllegalArgumentException {
        for (UsbPid pid : UsbPid.values()) {
            if (pid.value == value) {
                return pid;
            }
        }

        throw new IllegalArgumentException("invalid pid value");
    }
}
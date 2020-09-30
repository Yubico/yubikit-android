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
 * Provides constants for the different USB transports, and the Mode enum for combinations of enabled transports.
 */
public final class UsbTransport {
    public static final int OTP = 0x01;
    public static final int FIDO = 0x02;
    public static final int CCID = 0x04;

    private UsbTransport() {
    }

    public enum Mode {
        OTP((byte) 0x00, UsbTransport.OTP),
        CCID((byte) 0x01, UsbTransport.CCID),
        OTP_CCID((byte) 0x02, UsbTransport.OTP | UsbTransport.CCID),
        FIDO((byte) 0x03, UsbTransport.FIDO),
        OTP_FIDO((byte) 0x04, UsbTransport.OTP | UsbTransport.FIDO),
        FIDO_CCID((byte) 0x05, UsbTransport.FIDO | UsbTransport.CCID),
        OTP_FIDO_CCID((byte) 0x06, UsbTransport.OTP | UsbTransport.FIDO | UsbTransport.CCID);

        public final byte value;
        public final int transports;

        Mode(byte value, int transports) {
            this.value = value;
            this.transports = transports;
        }

        public static Mode getMode(int transports) {
            for (Mode mode : Mode.values()) {
                if (mode.transports == transports) {
                    return mode;
                }
            }
            throw new IllegalArgumentException("Invalid transports for Mode");
        }
    }
}

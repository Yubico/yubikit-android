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

package com.yubico.yubikit.core.smartcard;

public final class AppId {
    public static final byte[] MANAGEMENT = {(byte)0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17};
    public static final byte[] OTP = {(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01};
    public static final byte[] OATH = {(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01};
    public static final byte[] PIV = {(byte) 0xa0, 0x00, 0x00, 0x03, 0x08};
    public static final byte[] FIDO = {(byte) 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01};
    public static final byte[] OPENPGP = {(byte) 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01};
    public static final byte[] HSMAUTH = {(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x07, 0x01};
}

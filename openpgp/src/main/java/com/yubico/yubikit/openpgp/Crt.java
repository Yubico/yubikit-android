/*
 * Copyright (C) 2023 Yubico.
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

package com.yubico.yubikit.openpgp;

import com.yubico.yubikit.core.util.Tlv;

class Crt {
    static final byte[] SIG = new Tlv(0xb6, null).getBytes();
    static final byte[] DEC = new Tlv(0xb8, null).getBytes();
    static final byte[] AUT = new Tlv(0xa4, null).getBytes();
    static final byte[] ATT = new Tlv(0xb6, new Tlv(0x84, new byte[]{(byte) 0x81}).getBytes()).getBytes();
}

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

package com.yubico.yubikit.testing.piv;

import org.bouncycastle.util.encoders.Hex;

public class PivTestConstants {
    static final byte[] DEFAULT_MANAGEMENT_KEY = Hex.decode("010203040506070801020304050607080102030405060708");
    static final char[] DEFAULT_PIN = "123456".toCharArray();
    static final char[] DEFAULT_PUK = "12345678".toCharArray();
}

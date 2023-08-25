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

package com.yubico.yubikit.core.util;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Used internally in YubiKit, don't use from applications.
 */
public final class ByteUtils {
    /**
     * Serializes a BigInteger as an unsigned integer of the given length.
     * @param value the integer to serialize
     * @param length the length of the byte[] to return
     * @return the value as an unsigned integer
     */
    public static byte[] intToLength(BigInteger value, int length) {
        byte[] data = value.toByteArray();
        if (data.length == length) {
            return data;
        } else if (data.length < length) {
            byte[] padded = new byte[length];
            System.arraycopy(data, 0, padded, length - data.length, data.length);
            return padded;
        } else if (data.length == length + 1 && data[0] == 0) {
            // BigInteger may have a leading zero, since it's signed.
            return Arrays.copyOfRange(data, 1, data.length);
        } else {
            throw new IllegalArgumentException("value is too large to be represented in " + length + " bytes");
        }
    }
}

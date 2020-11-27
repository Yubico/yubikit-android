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
package com.yubico.yubikit.core.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Utility class to generate random data.
 */
public class RandomUtils {
    /**
     * Returns a byte array containing random values.
     */
    public static byte[] getRandomBytes(int length) {
        byte[] bytes = new byte[length];
        try {
            SecureRandom.getInstanceStrong().nextBytes(bytes);
        } catch (NoSuchMethodError | NoSuchAlgorithmException e) {
            // Fallback for older Android versions
            new SecureRandom().nextBytes(bytes);
        }
        return bytes;
    }

    private RandomUtils() {
        throw new IllegalStateException();
    }
}

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

package com.yubico.yubikit.oath;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Types of hash algorithms that can be used for TOTP using YubiKey OATH
 */
public enum HashAlgorithm {
    SHA1((byte)1, 64),
    SHA256((byte)2, 64),
    SHA512((byte)3, 128);

    public static final int MIN_KEY_SIZE = 14;

    public final byte value;
    public final int blockSize;

    HashAlgorithm(byte value, int blockSize) {
        this.value = value;
        this.blockSize = blockSize;
    }

    public byte[] prepareKey(byte[] key) throws NoSuchAlgorithmException {
        if (key.length < MIN_KEY_SIZE) {
            return ByteBuffer.allocate(MIN_KEY_SIZE).put(key).array();
        } else if (key.length > blockSize) {
            return MessageDigest.getInstance(name()).digest(key);
        } else {
            return key;
        }
    }

    public static HashAlgorithm fromValue(byte value) {
        for (HashAlgorithm type : HashAlgorithm.values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Not a valid HashAlgorithm");
    }

    public static HashAlgorithm fromString(String value) {
        if (value == null || value.isEmpty()) {
            return HashAlgorithm.SHA1;  //This is the default value
        }
        if ("sha1".equalsIgnoreCase(value)) {
            return HashAlgorithm.SHA1;
        }
        if ("sha256".equalsIgnoreCase(value)) {
            return HashAlgorithm.SHA256;
        }
        if ("sha512".equalsIgnoreCase(value)) {
            return HashAlgorithm.SHA512;
        }
        throw new IllegalArgumentException("Not a valid HashAlgorithm");
    }
}

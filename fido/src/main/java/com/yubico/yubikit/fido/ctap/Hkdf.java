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

package com.yubico.yubikit.fido.ctap;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5869">rfc5869</a>
 */
public class Hkdf {

    private final int length;
    private final byte[] salt;
    private final byte[] info;
    private final Mac mac;

    public Hkdf(String algo, @Nullable byte[] salt, byte[] info, int length) throws NoSuchAlgorithmException {
        this.salt = salt == null ? new byte[0] : salt;
        this.info = info;
        this.length = length;
        this.mac = Mac.getInstance(algo);
    }

    byte[] hmacDigest(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        mac.init(new SecretKeySpec(key, mac.getAlgorithm()));
        return mac.doFinal(data);
    }

    byte[] extract(byte[] salt, byte[] ikm) throws NoSuchAlgorithmException, InvalidKeyException {
        if (salt.length == 0) {
            int saltLen = mac.getMacLength();
            salt = new byte[saltLen];
        }
        return hmacDigest(salt, ikm);
    }

    byte[] expand(byte[] prk) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] t = new byte[0];
        byte[] okm = new byte[0];
        byte i = 0;
        while (okm.length < length) {
            i++;
            byte[] data = ByteBuffer.allocate(t.length + info.length + 1)
                    .put(t)
                    .put(info)
                    .put(i)
                    .array();
            t = hmacDigest(prk, data);

            okm = ByteBuffer.allocate(okm.length + t.length)
                    .put(okm)
                    .put(t)
                    .array();
        }

        return Arrays.copyOf(okm, length);
    }

    public byte[] digest(byte[] ikm) throws NoSuchAlgorithmException, InvalidKeyException {
        byte[] prk = extract(salt, ikm);
        return expand(prk);
    }
}

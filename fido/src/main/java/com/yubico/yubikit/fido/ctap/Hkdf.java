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
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc5869">rfc5869</a>
 */
class Hkdf {

  private final Mac mac;

  Hkdf(String algo) throws NoSuchAlgorithmException {
    this.mac = Mac.getInstance(algo);
  }

  byte[] hmacDigest(byte[] key, byte[] data) throws InvalidKeyException {
    mac.init(new SecretKeySpec(key, mac.getAlgorithm()));
    return mac.doFinal(data);
  }

  byte[] extract(byte[] salt, byte[] ikm) throws InvalidKeyException {
    return hmacDigest(salt.length != 0 ? salt : new byte[mac.getMacLength()], ikm);
  }

  byte[] expand(byte[] prk, byte[] info, int length) throws InvalidKeyException {
    byte[] t = new byte[0];
    byte[] okm = new byte[0];
    byte i = 0;
    while (okm.length < length) {
      i++;
      byte[] data = ByteBuffer.allocate(t.length + info.length + 1).put(t).put(info).put(i).array();
      Arrays.fill(t, (byte) 0);
      byte[] digest = hmacDigest(prk, data);

      byte[] result = ByteBuffer.allocate(okm.length + digest.length).put(okm).put(digest).array();
      Arrays.fill(okm, (byte) 0);
      Arrays.fill(data, (byte) 0);
      okm = result;
      t = digest;
    }

    byte[] result = Arrays.copyOf(okm, length);
    Arrays.fill(okm, (byte) 0);
    return result;
  }

  byte[] digest(byte[] ikm, byte[] salt, byte[] info, int length) throws InvalidKeyException {
    byte[] prk = extract(salt, ikm);
    byte[] result = expand(prk, info, length);
    Arrays.fill(prk, (byte) 0);
    return result;
  }
}

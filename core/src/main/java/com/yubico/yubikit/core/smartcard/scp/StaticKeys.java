/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.core.smartcard.scp;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class StaticKeys {
  private static final byte[] DEFAULT_KEY =
      new byte[] {
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
      };

  final SecretKey enc;
  final SecretKey mac;
  @Nullable final SecretKey dek;

  public StaticKeys(byte[] enc, byte[] mac, @Nullable byte[] dek) {
    this.enc = new SecretKeySpec(enc, "AES");
    this.mac = new SecretKeySpec(mac, "AES");
    this.dek = dek != null ? new SecretKeySpec(dek, "AES") : null;
  }

  public SessionKeys derive(byte[] context) {
    return new SessionKeys(
        deriveKey(enc, (byte) 0x4, context, (short) 0x80),
        deriveKey(mac, (byte) 0x6, context, (short) 0x80),
        deriveKey(mac, (byte) 0x7, context, (short) 0x80),
        dek);
  }

  public static StaticKeys getDefaultKeys() {
    return new StaticKeys(DEFAULT_KEY, DEFAULT_KEY, DEFAULT_KEY);
  }

  static SecretKey deriveKey(SecretKey key, byte t, byte[] context, short l) {
    if (!(l == 0x40 || l == 0x80)) {
      throw new IllegalArgumentException("l must be 0x40 or 0x80");
    }
    byte[] i =
        ByteBuffer.allocate(16 + context.length)
            .put(new byte[11])
            .put(t)
            .put((byte) 0)
            .putShort(l)
            .put((byte) 1)
            .put(context)
            .array();

    byte[] digest = null;
    try {
      Mac mac = Mac.getInstance("AESCMAC");
      mac.init(key);
      digest = mac.doFinal(i);
      return new SecretKeySpec(digest, 0, l / 8, "AES");
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new UnsupportedOperationException("Cryptography provider does not support AESCMAC", e);
    } finally {
      if (digest != null) {
        Arrays.fill(digest, (byte) 0);
      }
    }
  }
}

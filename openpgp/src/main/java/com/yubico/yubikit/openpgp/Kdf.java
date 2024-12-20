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

import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

public abstract class Kdf {
  protected final byte algorithm;

  protected Kdf(byte algorithm) {
    this.algorithm = algorithm;
  }

  public byte getAlgorithm() {
    return algorithm;
  }

  abstract byte[] process(Pw pw, char[] pin);

  abstract byte[] getBytes();

  public static Kdf parse(byte[] encoded) {
    Map<Integer, byte[]> data = Tlvs.decodeMap(encoded);
    byte algorithm = data.getOrDefault(0x81, new byte[] {0})[0];
    if (algorithm == 3) {
      return IterSaltedS2k.parseData(data);
    }
    return new None();
  }

  public static class None extends Kdf {
    public None() {
      super((byte) 0);
    }

    @Override
    public byte[] process(Pw pw, char[] pin) {
      return pinBytes(pin);
    }

    @Override
    public byte[] getBytes() {
      return new Tlv(0x81, new byte[] {algorithm}).getBytes();
    }
  }

  public static class IterSaltedS2k extends Kdf {
    public enum HashAlgorithm {
      SHA256((byte) 0x08),
      SHA512((byte) 0x0a);
      private final byte value;

      HashAlgorithm(byte value) {
        this.value = value;
      }

      private MessageDigest getMessageDigest() {
        try {
          return MessageDigest.getInstance(name());
        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(e);
        }
      }

      static HashAlgorithm forValue(byte value) {
        for (HashAlgorithm alg : HashAlgorithm.values()) {
          if (alg.value == value) {
            return alg;
          }
        }
        throw new IllegalArgumentException("Not a valid HashAlgorithm");
      }
    }

    private final HashAlgorithm hashAlgorithm;
    private final int iterationCount;
    private final byte[] saltUser;
    @Nullable private final byte[] saltReset;
    @Nullable private final byte[] saltAdmin;
    @Nullable private final byte[] initialHashUser;
    @Nullable private final byte[] initialHashAdmin;

    public IterSaltedS2k(
        HashAlgorithm hashAlgorithm,
        int iterationCount,
        byte[] saltUser,
        @Nullable byte[] saltReset,
        @Nullable byte[] saltAdmin,
        @Nullable byte[] initialHashUser,
        @Nullable byte[] initialHashAdmin) {
      super((byte) 3);
      this.hashAlgorithm = hashAlgorithm;
      this.iterationCount = iterationCount;
      this.saltUser = saltUser;
      this.saltReset = saltReset;
      this.saltAdmin = saltAdmin;
      this.initialHashUser = initialHashUser;
      this.initialHashAdmin = initialHashAdmin;
    }

    static IterSaltedS2k parseData(Map<Integer, byte[]> data) {
      return new IterSaltedS2k(
          HashAlgorithm.forValue(data.get(0x82)[0]),
          new BigInteger(1, data.get(0x83)).intValue(),
          data.get(0x84),
          data.get(0x85),
          data.get(0x86),
          data.get(0x87),
          data.get(0x88));
    }

    private byte[] getSalt(Pw pw) {
      switch (pw) {
        case USER:
          return saltUser;
        case RESET:
          return saltReset != null ? saltReset : saltUser;
        case ADMIN:
          return saltAdmin != null ? saltAdmin : saltUser;
        default:
          throw new IllegalArgumentException();
      }
    }

    private static byte[] doProcess(HashAlgorithm hashAlgorithm, int iterationCount, byte[] data) {
      // "iterationCount" is actually the total number of bytes to pass to the digest.
      int dataCount = iterationCount / data.length;
      int trailingBytes = iterationCount % data.length;
      MessageDigest md = hashAlgorithm.getMessageDigest();
      for (int i = 0; i < dataCount; i++) {
        md.update(data);
      }
      md.update(data, 0, trailingBytes);
      return md.digest();
    }

    @Override
    public byte[] process(Pw pw, char[] pin) {
      byte[] pinBytes = null;
      byte[] data = null;
      try {
        final byte[] salt = getSalt(pw);
        pinBytes = pinBytes(pin);
        data = ByteBuffer.allocate(salt.length + pinBytes.length).put(salt).put(pinBytes).array();
        return doProcess(hashAlgorithm, iterationCount, data);
      } finally {
        if (pinBytes != null) {
          Arrays.fill(pinBytes, (byte) 0);
        }
        if (data != null) {
          Arrays.fill(data, (byte) 0);
        }
      }
    }

    @Override
    public byte[] getBytes() {
      List<Tlv> tlvs = new ArrayList<>();
      tlvs.add(new Tlv(0x81, new byte[] {algorithm}));
      tlvs.add(new Tlv(0x82, new byte[] {hashAlgorithm.value}));
      tlvs.add(new Tlv(0x83, ByteBuffer.allocate(4).putInt(iterationCount).array()));
      tlvs.add(new Tlv(0x84, saltUser));
      if (saltReset != null) {
        tlvs.add(new Tlv(0x85, saltReset));
      }
      if (saltAdmin != null) {
        tlvs.add(new Tlv(0x86, saltAdmin));
      }
      if (initialHashUser != null) {
        tlvs.add(new Tlv(0x87, initialHashUser));
      }
      if (initialHashAdmin != null) {
        tlvs.add(new Tlv(0x88, initialHashAdmin));
      }

      return Tlvs.encodeList(tlvs);
    }

    public static IterSaltedS2k create(HashAlgorithm hashAlgorithm, int iterationCount) {
      byte[] saltUser = RandomUtils.getRandomBytes(8);
      byte[] saltAdmin = RandomUtils.getRandomBytes(8);
      byte[] defaultUserPinEncoded = pinBytes(Pw.DEFAULT_USER_PIN);
      byte[] defaultAdminPinEncoded = pinBytes(Pw.DEFAULT_ADMIN_PIN);
      return new IterSaltedS2k(
          hashAlgorithm,
          iterationCount,
          saltUser,
          RandomUtils.getRandomBytes(8),
          saltAdmin,
          doProcess(
              hashAlgorithm,
              iterationCount,
              ByteBuffer.allocate(8 + defaultUserPinEncoded.length)
                  .put(saltUser)
                  .put(defaultUserPinEncoded)
                  .array()),
          doProcess(
              hashAlgorithm,
              iterationCount,
              ByteBuffer.allocate(8 + defaultAdminPinEncoded.length)
                  .put(saltAdmin)
                  .put(defaultAdminPinEncoded)
                  .array()));
    }
  }

  private static byte[] pinBytes(char[] pin) {
    ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(pin));
    try {
      return Arrays.copyOf(byteBuffer.array(), byteBuffer.limit());
    } finally {
      Arrays.fill(byteBuffer.array(), (byte) 0);
    }
  }
}

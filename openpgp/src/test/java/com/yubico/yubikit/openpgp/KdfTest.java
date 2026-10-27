/*
 * Copyright (C) 2026 Yubico.
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;

import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

public class KdfTest {
  private static final byte[] SALT = {1, 2, 3, 4, 5, 6, 7, 8};
  private static final char[] PIN = "123456".toCharArray();

  private static byte[] encode(byte[] count) {
    List<Tlv> tlvs = new ArrayList<>();
    tlvs.add(new Tlv(0x81, new byte[] {3}));
    tlvs.add(new Tlv(0x82, new byte[] {0x08}));
    tlvs.add(new Tlv(0x83, count));
    tlvs.add(new Tlv(0x84, SALT));
    return Tlvs.encodeList(tlvs);
  }

  private static byte[] count(int value) {
    return ByteBuffer.allocate(4).putInt(value).array();
  }

  private static byte[] expected(int total) throws Exception {
    byte[] pin = new String(PIN).getBytes(StandardCharsets.UTF_8);
    byte[] block = ByteBuffer.allocate(SALT.length + pin.length).put(SALT).put(pin).array();
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    int written = 0;
    while (written < total) {
      int n = Math.min(block.length, total - written);
      md.update(block, 0, n);
      written += n;
    }
    return md.digest();
  }

  @Test
  public void parsesNormalCount() throws Exception {
    Kdf kdf = Kdf.parse(encode(count(1024)));
    assertArrayEquals(expected(1024), kdf.process(Pw.USER, PIN));
  }

  @Test
  public void parsesSmallPositiveCount() throws Exception {
    Kdf kdf = Kdf.parse(encode(count(20)));
    assertArrayEquals(expected(20), kdf.process(Pw.USER, PIN));
  }

  @Test
  public void countSmallerThanBlockHashesWholeBlock() throws Exception {
    byte[] block = expected(SALT.length + PIN.length);
    for (int c : new int[] {1, SALT.length + PIN.length - 1}) {
      Kdf kdf = Kdf.parse(encode(count(c)));
      assertArrayEquals(block, kdf.process(Pw.USER, PIN));
    }
  }

  @Test
  public void shortCountDependsOnPin() {
    Kdf kdf = Kdf.parse(encode(count(1)));
    assertFalse(
        Arrays.equals(
            kdf.process(Pw.USER, "123456".toCharArray()),
            kdf.process(Pw.USER, "654321".toCharArray())));
  }

  @Test
  public void rejectsZeroCount() {
    assertThrows(IllegalArgumentException.class, () -> Kdf.parse(encode(count(0))));
  }

  @Test
  public void rejectsFiveByteCountThatTruncates() {
    assertThrows(
        IllegalArgumentException.class,
        () -> Kdf.parse(encode(new byte[] {0x01, 0x00, 0x00, 0x04, 0x00})));
  }

  @Test
  public void rejectsShortAndEmptyCount() {
    assertThrows(IllegalArgumentException.class, () -> Kdf.parse(encode(new byte[] {0x04, 0x00})));
    assertThrows(IllegalArgumentException.class, () -> Kdf.parse(encode(new byte[0])));
  }

  @Test
  public void rejectsHighBitCount() {
    assertThrows(
        IllegalArgumentException.class, () -> Kdf.parse(encode(new byte[] {-1, -1, -1, -1})));
    assertThrows(
        IllegalArgumentException.class, () -> Kdf.parse(encode(new byte[] {-128, 0, 0, 0})));
  }

  @Test
  public void acceptsMaxSupportedCount() {
    Kdf.IterSaltedS2k kdf = (Kdf.IterSaltedS2k) Kdf.parse(encode(count(Integer.MAX_VALUE)));
    assertEquals(3, kdf.getAlgorithm());
    assertArrayEquals(count(Integer.MAX_VALUE), Tlvs.decodeMap(kdf.getBytes()).get(0x83));
  }

  @Test
  public void constructorRejectsNonPositiveCount() {
    for (int c : new int[] {0, -1, Integer.MIN_VALUE}) {
      assertThrows(
          IllegalArgumentException.class,
          () ->
              new Kdf.IterSaltedS2k(
                  Kdf.IterSaltedS2k.HashAlgorithm.SHA256, c, SALT, null, null, null, null));
    }
  }
}

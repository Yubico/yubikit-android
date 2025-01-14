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

package com.yubico.yubikit.oath;

import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Base32 implementation of RFC4684, section 6
 *
 * @see <a href="https://datatracker.ietf.org/doc/html/rfc4648#section-6">Base 32 Encoding</a>
 */
@SuppressWarnings("SpellCheckingInspection")
public class Base32 {
  private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();

  private static final char PADDING = '=';

  private static final String[] ENCODE_PADDING = new String[] {"", "======", "====", "===", "="};

  public static String encode(byte[] data) {
    StringBuilder buf = new StringBuilder();

    int len = data.length;
    for (int i = 0; i < len; i += 5) {
      int b0 = Byte.toUnsignedInt(data[i]);
      int b1 = len > i + 1 ? Byte.toUnsignedInt(data[i + 1]) : 0;
      int b2 = len > i + 2 ? Byte.toUnsignedInt(data[i + 2]) : 0;
      int b3 = len > i + 3 ? Byte.toUnsignedInt(data[i + 3]) : 0;
      int b4 = len > i + 4 ? Byte.toUnsignedInt(data[i + 4]) : 0;

      buf.append(ALPHABET[b0 >> 3]);
      buf.append(ALPHABET[b0 << 2 & 0x1c | b1 >> 6]);
      if (len <= i + 1) break;
      buf.append(ALPHABET[b1 >> 1 & 0x1f]);
      buf.append(ALPHABET[b1 << 4 & 0x10 | b2 >> 4]);
      if (len <= i + 2) break;
      buf.append(ALPHABET[b2 << 1 & 0x1e | b3 >> 7]);
      if (len <= i + 3) break;
      buf.append(ALPHABET[b3 >> 2 & 0x1f]);
      buf.append(ALPHABET[b3 << 3 & 0x1c | b4 >> 5]);
      if (len <= i + 4) break;
      buf.append(ALPHABET[b4 & 0x1f]);
    }

    buf.append(ENCODE_PADDING[len % 5]);
    return buf.toString();
  }

  public static boolean isValid(String encoded) {
    if (!encoded.matches("^$|^[A-Z2-7]{2,}(=*)$")) {
      return false;
    }

    int finalUnitLength = encoded.length() % 8;
    int paddingIndex = encoded.indexOf("=");
    if (paddingIndex == -1) {
      // no padding; input is valid only if a correct padding can be appended
      return finalUnitLength == 0
          || finalUnitLength == 7
          || finalUnitLength == 5
          || finalUnitLength == 4
          || finalUnitLength == 2;
    }

    if (finalUnitLength != 0) {
      // wrong input length
      return false;
    }

    int paddingLength = encoded.length() - paddingIndex;
    // padding can only be 1, 3, 4 or 6 characters long, otherwise this is not a valid input
    return paddingLength == 1 || paddingLength == 3 || paddingLength == 4 || paddingLength == 6;
  }

  public static byte[] decode(String encoded) {

    if (!isValid(encoded)) {
      throw new IllegalArgumentException("Invalid base32");
    }

    char[] padding = new char[(8 - encoded.length() % 8) % 8];
    Arrays.fill(padding, PADDING);
    String b32 = encoded.concat(new String(padding));

    int len = b32.length();
    int maxBufLength = len / 8 * 5;
    byte[] buffer = new byte[maxBufLength];

    ByteBuffer bb = ByteBuffer.wrap(buffer);

    for (int i = 0; i < b32.length(); i += 8) {
      final char[] chars = b32.toCharArray();

      // input characters
      char c0 = chars[i];
      char c1 = chars[i + 1];
      char c2 = chars[i + 2];
      char c3 = chars[i + 3];
      char c4 = chars[i + 4];
      char c5 = chars[i + 5];
      char c6 = chars[i + 6];
      char c7 = chars[i + 7];

      // input values
      byte v0 = getValue(c0);
      byte v1 = getValue(c1);
      byte v2 = getValue(c2);
      byte v3 = getValue(c3);
      byte v4 = getValue(c4);
      byte v5 = getValue(c5);
      byte v6 = getValue(c6);
      byte v7 = getValue(c7);

      // build result until padding is found
      bb.put((byte) (v0 << 3 | v1 >> 2));
      if (c2 == PADDING) break;
      bb.put((byte) (v1 << 6 | v2 << 1 | v3 >> 4));
      if (c3 == PADDING) break;
      bb.put((byte) (v3 << 4 | v4 >> 1));
      if (c4 == PADDING) break;
      bb.put((byte) (v4 << 7 | v5 << 2 | v6 >> 3));
      if (c6 == PADDING) break;
      bb.put((byte) (v6 << 5 | v7));
    }

    // update result length
    int resultLength = bb.position();
    byte[] result =
        Arrays.copyOf(
            buffer,
            (resultLength > 0 && buffer[resultLength - 1] == 0)
                ? resultLength - 1 // strip last byte if 0
                : resultLength);
    Arrays.fill(buffer, (byte) 0);
    return result;
  }

  private static byte getValue(char c) {
    // compute the value
    // if c is the padding character, use 0 to simplify bit operations
    return c == PADDING ? 0 : (byte) ((c < 'A' ? c - '2' + 26 : c - 'A') & 0x1f);
  }
}

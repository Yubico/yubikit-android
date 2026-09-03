/*
 * Copyright (C) 2019-2025 Yubico.
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

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Locale;
import org.jspecify.annotations.Nullable;

/**
 * Tag, length, Value structure that helps to parse APDU response data.
 *
 * <p>This class handles BER-TLV encoded data with determinate length.
 */
public class Tlv {
  /** Maximum number of bytes in a tag, bounded by the int the tag is decoded into. */
  private static final int MAX_TAG_BYTES = 4;

  /** Maximum number of bytes in a long form length, bounded by the int it is decoded into. */
  private static final int MAX_LENGTH_BYTES = 4;

  private final int tag;
  private final int length;
  private final byte[] bytes;
  private final int offset;

  /** Creates a new Tlv given a tag and a value. */
  public Tlv(int tag, byte @Nullable [] value) {
    this.tag = tag;
    ByteArrayOutputStream stream = new ByteArrayOutputStream();

    byte[] tagBytes = BigInteger.valueOf(tag).toByteArray();
    int stripLeading = tagBytes[0] == 0 ? 1 : 0;
    stream.write(tagBytes, stripLeading, tagBytes.length - stripLeading);

    length = value == null ? 0 : value.length;
    if (length < 0x80) {
      stream.write(length);
    } else {
      byte[] lnBytes = BigInteger.valueOf(length).toByteArray();
      stripLeading = lnBytes[0] == 0 ? 1 : 0;
      stream.write(0x80 | lnBytes.length - stripLeading);
      stream.write(lnBytes, stripLeading, lnBytes.length - stripLeading);
    }

    offset = stream.size();
    if (value != null) {
      stream.write(value, 0, length);
    }
    bytes = stream.toByteArray();
  }

  /** Returns the tag. */
  public int getTag() {
    return tag;
  }

  /** returns the value. */
  public byte[] getValue() {
    return Arrays.copyOfRange(bytes, offset, offset + length);
  }

  /** Returns the length of the value. */
  public int getLength() {
    return length;
  }

  /** Returns the Tlv as a BER-TLV encoded byte array. */
  public byte[] getBytes() {
    return Arrays.copyOf(bytes, bytes.length);
  }

  @Override
  public String toString() {
    return String.format(
        Locale.ROOT, "Tlv(0x%x, %d, %s)", tag, length, StringUtils.bytesToHex(getValue()));
  }

  /**
   * Parse a Tlv from a BER-TLV encoded byte array.
   *
   * @param data a byte array containing the TLV encoded data.
   * @param offset the offset in data where the TLV data begins.
   * @param length the length of the TLV encoded data.
   * @return The parsed Tlv
   */
  public static Tlv parse(byte[] data, int offset, int length) {
    ByteBuffer buffer = ByteBuffer.wrap(data, offset, length);
    Tlv tlv = parseFrom(buffer);
    if (buffer.hasRemaining()) {
      throw new IllegalArgumentException("Extra data remaining");
    }
    return tlv;
  }

  /**
   * Parse a Tlv from a BER-TLV encoded byte array.
   *
   * @param data a byte array containing the TLV encoded data (and nothing more).
   * @return The parsed Tlv
   */
  public static Tlv parse(byte[] data) {
    return parse(data, 0, data.length);
  }

  static Tlv parseFrom(ByteBuffer buffer) {
    int tag = buffer.get() & 0xFF;
    if ((tag & 0x1F) == 0x1F) { // Long form tag
      tag = (tag << 8) | (buffer.get() & 0xFF);
      int tagBytes = 2;
      while ((tag & 0x80) == 0x80) {
        // Without this the shift below silently overflows the int and misparses the tag.
        if (tagBytes == MAX_TAG_BYTES) {
          throw new IllegalArgumentException(
              String.format(Locale.ROOT, "Tag exceeds %d bytes", MAX_TAG_BYTES));
        }
        tag = (tag << 8) | (buffer.get() & 0xFF);
        tagBytes++;
      }
    }

    int length = buffer.get() & 0xFF;
    if (length == 0x80) {
      throw new IllegalArgumentException("Indefinite length not supported");
    } else if (length > 0x80) {
      int lengthLn = length - 0x80;
      // A long form length may declare up to 127 bytes; anything past 4 overflows the int below,
      // which would silently wrap to a plausible looking (and wrong) length.
      if (lengthLn > MAX_LENGTH_BYTES) {
        throw new IllegalArgumentException(
            String.format(Locale.ROOT, "Length exceeds %d bytes", MAX_LENGTH_BYTES));
      }
      length = 0;
      for (int i = 0; i < lengthLn; i++) {
        length = (length << 8) | (buffer.get() & 0xff);
      }
      if (length < 0) {
        throw new IllegalArgumentException("Length exceeds Integer.MAX_VALUE");
      }
    }

    // Check the declared length against what is actually available before allocating. Allocating
    // first lets a malformed length of e.g. 0x7FFFFFFF raise an OutOfMemoryError, which is an
    // Error rather than the BufferUnderflowException callers expect from a truncated response.
    if (length > buffer.remaining()) {
      throw new BufferUnderflowException();
    }

    byte[] value = new byte[length];
    buffer.get(value);
    return new Tlv(tag, value);
  }
}

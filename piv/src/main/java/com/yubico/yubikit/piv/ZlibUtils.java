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

package com.yubico.yubikit.piv;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.zip.DataFormatException;
import java.util.zip.Deflater;
import java.util.zip.Inflater;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utilities for compressing and decompressing data in a zlib format with a custom header.
 *
 * <p>This is <b>not</b> standard zlib. This format wraps zlib-compressed data with a 4-byte header
 * and is used by some smart cards, including Generic Identity Device Specification (GIDS) cards:
 *
 * <ul>
 *   <li>Bytes 0-1: Magic bytes (0x01, 0x00)
 *   <li>Bytes 2-3: Expected decompressed length (16-bit little-endian, max 65535 bytes)
 *   <li>Bytes 4+: Standard zlib-compressed data
 * </ul>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc1950">RFC1950</a>
 */
class ZlibUtils {
  private static final Logger logger = LoggerFactory.getLogger(ZlibUtils.class);
  private static final int MAX_INPUT_LENGTH = 0xFFFF; // 65535 bytes (16-bit length field)

  /**
   * Compress data using zlib format with custom header.
   *
   * @param input byte array to be compressed (max 65535 bytes)
   * @return byte array with 4-byte header and compressed data
   * @throws IllegalArgumentException if input exceeds 65535 bytes
   */
  static byte[] compress(byte[] input) {
    if (input.length > MAX_INPUT_LENGTH) {
      throw new IllegalArgumentException(
          "Input data too large for zlib format: "
              + input.length
              + " bytes (max "
              + MAX_INPUT_LENGTH
              + ")");
    }
    logger.debug("Compressing {} bytes using zlib", input.length);
    Deflater deflater = new Deflater();
    deflater.setInput(input);
    deflater.finish();
    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    byte[] buffer = new byte[512];
    while (!deflater.finished()) {
      int count = deflater.deflate(buffer);
      outputStream.write(buffer, 0, count);
    }
    deflater.end();
    byte[] compressed = outputStream.toByteArray();

    // Build zlib format with header: 0x01, 0x00, length (little endian), compressed data
    ByteBuffer result = ByteBuffer.allocate(4 + compressed.length);
    result.put((byte) 0x01);
    result.put((byte) 0x00);
    result.order(ByteOrder.LITTLE_ENDIAN).putShort((short) input.length);
    result.put(compressed);

    logger.debug("Compressed to {} bytes (including 4-byte header)", result.array().length);
    return result.array();
  }

  /**
   * Decompress data in zlib format with custom header.
   *
   * @param input byte array with 4-byte header and compressed data
   * @return decompressed data
   * @throws IOException if the decompression failed or length mismatch
   */
  static byte[] decompress(byte[] input) throws IOException {
    logger.debug("Decompressing {} bytes using zlib", input.length);
    if (input.length < 4) {
      throw new IOException("Zlib compressed data too short");
    }
    int expectedLength =
        ByteBuffer.wrap(input, 2, 2).order(ByteOrder.LITTLE_ENDIAN).getShort() & 0xFFFF;

    try {
      Inflater inflater = new Inflater();
      inflater.setInput(input, 4, input.length - 4);
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream(expectedLength);
      byte[] buffer = new byte[512];
      while (!inflater.finished()) {
        int count = inflater.inflate(buffer);
        outputStream.write(buffer, 0, count);
      }
      inflater.end();
      byte[] decompressed = outputStream.toByteArray();

      if (decompressed.length != expectedLength) {
        logger.error(
            "Unexpected decompressed length, expected {}, got {}",
            expectedLength,
            decompressed.length);
        throw new IOException("Decompressed length does not match expected length");
      }

      logger.debug("Decompressed to {} bytes", decompressed.length);
      return decompressed;
    } catch (DataFormatException e) {
      throw new IOException("Failed to decompress zlib data", e);
    }
  }
}

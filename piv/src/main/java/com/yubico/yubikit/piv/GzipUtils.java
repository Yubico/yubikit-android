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

package com.yubico.yubikit.piv;

import com.yubico.yubikit.core.internal.Logger;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;
import org.slf4j.LoggerFactory;

/**
 * Utilities for GZIP
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc1952">RFC1952</a>
 */
public class GzipUtils {
  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(GzipUtils.class);

  /**
   * @param input byte array to be compressed
   * @return byte array of gzip compressed data
   * @throws IOException if the compression failed
   */
  static byte[] compress(byte[] input) throws IOException {
    Logger.debug(logger, "Compressing {} bytes", input.length);
    try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream(input.length);
        GZIPOutputStream gzipOutputStream = new GZIPOutputStream(byteArrayOutputStream)) {
      gzipOutputStream.write(input);
      gzipOutputStream.finish();
      Logger.debug(logger, "Compressed to {} bytes", byteArrayOutputStream.size());
      return byteArrayOutputStream.toByteArray();
    }
  }

  /**
   * @param input byte array of gzip data to be uncompressed
   * @return uncompressed data
   * @throws IOException if the decompression failed
   */
  static byte[] decompress(byte[] input) throws IOException {
    Logger.debug(logger, "Decompressing {} bytes", input.length);
    final int BUFFER_SIZE = 512;
    byte[] buffer = new byte[BUFFER_SIZE];
    int bytesRead;
    try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(input);
        GZIPInputStream gzipInputStream = new GZIPInputStream(byteArrayInputStream)) {

      while ((bytesRead = gzipInputStream.read(buffer, 0, BUFFER_SIZE)) != -1) {
        byteArrayOutputStream.write(buffer, 0, bytesRead);
      }

      Logger.debug(logger, "Decompressed to {} bytes", byteArrayOutputStream.size());
      return byteArrayOutputStream.toByteArray();
    }
  }
}

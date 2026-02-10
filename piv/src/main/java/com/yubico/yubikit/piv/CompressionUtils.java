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

import java.io.IOException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Facade for certificate compression/decompression using various methods.
 *
 * <p>Supports gzip (0x1F, 0x8B header) and zlib with custom header (0x01, 0x00 header).
 */
class CompressionUtils {
  private static final Logger logger = LoggerFactory.getLogger(CompressionUtils.class);

  /**
   * Decompress a compressed certificate using various methods.
   *
   * <p>Detects the compression format based on the header bytes and delegates to the appropriate
   * decompression utility.
   *
   * @param certData byte array of compressed certificate data
   * @return uncompressed certificate data
   * @throws IOException if decompression failed or unknown compression format
   */
  // TODO: remove @SuppressWarnings once GzipUtils is made package-private
  @SuppressWarnings("deprecation")
  static byte[] decompressCertificate(byte[] certData) throws IOException {
    logger.debug("Certificate is compressed, decompressing...");

    if (certData.length < 2) {
      throw new IOException("Compressed certificate data too short");
    }

    int firstByte = certData[0] & 0xFF;
    int secondByte = certData[1] & 0xFF;

    // Gzip format (most commonly used)
    if (firstByte == 0x1F && secondByte == 0x8B) {
      logger.debug("Decompressing certificate using gzip");
      return GzipUtils.decompress(certData);
    }

    // Zlib with custom header format
    if (firstByte == 0x01 && secondByte == 0x00) {
      logger.debug("Decompressing certificate using zlib");
      return ZlibUtils.decompress(certData);
    }

    logger.warn("Unknown compression type");
    throw new IOException("Unknown compression type");
  }
}

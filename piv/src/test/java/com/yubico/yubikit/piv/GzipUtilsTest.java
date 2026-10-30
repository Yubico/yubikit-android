/*
 * Copyright (C) 2023-2026 Yubico.
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

import static com.yubico.yubikit.piv.GzipUtils.compress;
import static com.yubico.yubikit.piv.GzipUtils.decompress;

import com.yubico.yubikit.Codec;
import com.yubico.yubikit.core.util.StringUtils;
import java.io.EOFException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.zip.ZipException;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// TODO: remove @SuppressWarnings once GzipUtils is made package-private
@SuppressWarnings("deprecation")
public class GzipUtilsTest {

  private static final Logger logger = LoggerFactory.getLogger(GzipUtilsTest.class);

  private final byte[] testData =
      Codec.fromHex(
          "1f8b08000000000000008b2c4dcaf4ce2c5148cb2f5270cc4b29cacf4c5128492d2e5148492c49040003f7e"
              + "f7d1d000000");

  @Test
  public void compressesEmptyData() throws Throwable {
    compressAndDecompress(new byte[0]);
  }

  @Test
  public void compressesShortData() throws Throwable {
    compressAndDecompress("YubiKit".getBytes(StandardCharsets.ISO_8859_1));
  }

  @Test
  public void compressesBigData() throws Throwable {
    byte[] data = new byte[CompressionUtils.MAX_DECOMPRESSED_LENGTH]; // the largest accepted
    for (int index = 0; index < data.length; index++) {
      data[index] = (byte) ((index & 0xff) - (byte) (index >> 8) * (index & 0xef));
    }
    compressAndDecompress(data);
  }

  @Test(expected = IOException.class)
  public void decompressRejectsOutputOverLimit() throws Throwable {
    decompress(compress(new byte[CompressionUtils.MAX_DECOMPRESSED_LENGTH + 1]));
  }

  /** A few KB of gzip that would expand to 64 MiB must be refused, not inflated. */
  @Test(expected = IOException.class, timeout = 5000)
  public void decompressRejectsExpansionBomb() throws Throwable {
    decompress(compress(new byte[64 * 1024 * 1024]));
  }

  @Test(expected = EOFException.class)
  public void decompressEmptyData() throws Throwable {
    byte[] d = decompress(new byte[0]);
    Assert.assertEquals(0, d.length);
  }

  @Test(expected = ZipException.class)
  public void decompressInvalidData() throws Throwable {
    decompress(new byte[] {1, 2, 3, 4});
  }

  @Test
  public void decompressGzipedData() throws Throwable {
    String s = new String(decompress(testData), StandardCharsets.ISO_8859_1);
    Assert.assertEquals("YubiKit for Android test data", s);
  }

  private void compressAndDecompress(byte[] data) throws Throwable {
    byte[] c = compress(data);
    byte[] d = decompress(c);
    if (data.length < 1024) { // don't log our 128kB test
      logger.trace("Data to compress  : {}", StringUtils.bytesToHex(data));
      logger.trace("compressed data   : {}", StringUtils.bytesToHex(c));
      logger.trace("Decompressed data : {}", StringUtils.bytesToHex(d));
    }
    Assert.assertArrayEquals(data, d);
  }
}

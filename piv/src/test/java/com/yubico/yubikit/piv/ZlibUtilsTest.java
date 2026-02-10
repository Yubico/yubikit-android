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

import static com.yubico.yubikit.piv.ZlibUtils.compress;
import static com.yubico.yubikit.piv.ZlibUtils.decompress;

import com.yubico.yubikit.Codec;
import com.yubico.yubikit.core.util.StringUtils;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.Assert;
import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ZlibUtilsTest {

  private static final Logger logger = LoggerFactory.getLogger(ZlibUtilsTest.class);

  /**
   * Zlib format with custom header: 0x01, 0x00, length (little-endian), zlib-compressed "YubiKit
   * for Android test data"
   *
   * <p>Generated with:
   *
   * <pre>
   * import zlib
   * d = b'YubiKit for Android test data'
   * c = zlib.compress(d)
   * print((b'\x01\x00' + len(d).to_bytes(2,'little') + c).hex())
   * </pre>
   */
  private static final byte[] zlibTestData =
      Codec.fromHex(
          "01001d00789c8b2c4dcaf4ce2c5148cb2f5270cc4b29cacf4c5128492d2e5148492c4904009f2e0aa4");

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
    byte[] data = new byte[32 * 1024]; // 32kB (must fit in 16-bit length header)
    for (int index = 0; index < data.length; index++) {
      data[index] = (byte) ((index & 0xff) - (byte) (index >> 8) * (index & 0xef));
    }
    compressAndDecompress(data);
  }

  @Test(expected = IOException.class)
  public void decompressTooShort() throws Throwable {
    decompress(new byte[] {0x01, 0x00, 0x01});
  }

  @Test(expected = IOException.class)
  public void decompressLengthMismatch() throws Throwable {
    byte[] compressed = zlibTestData.clone();
    // Modify the expected length in the header to be wrong
    compressed[2] = (byte) 0xFF;
    compressed[3] = (byte) 0x03;
    decompress(compressed);
  }

  @Test(expected = IllegalArgumentException.class)
  public void compressInputTooLarge() {
    byte[] data = new byte[65536]; // One byte over the 64KB limit
    compress(data);
  }

  @Test
  public void decompressZlibData() throws Throwable {
    String s = new String(decompress(zlibTestData), StandardCharsets.ISO_8859_1);
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

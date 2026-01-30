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

import static com.yubico.yubikit.piv.CompressionUtils.decompressCertificate;

import com.yubico.yubikit.Codec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.junit.Assert;
import org.junit.Test;

public class CompressionUtilsTest {

  private final byte[] gzipTestData =
      Codec.fromHex(
          "1f8b08000000000000008b2c4dcaf4ce2c5148cb2f5270cc4b29cacf4c5128492d2e5148492c49040003f7e"
              + "f7d1d000000");

  // Net iD zlib format test data (same string as gzipTestData)
  private static final byte[] netIdZlibTestData =
      Codec.fromHex(
          "01001d00789c8b2c4dcaf4ce2c5148cb2f5270cc4b29cacf4c5128492d2e5148492c4904009f2e0aa4");

  @Test
  public void decompressCertificateGzip() throws Throwable {
    String s = new String(decompressCertificate(gzipTestData), StandardCharsets.ISO_8859_1);
    Assert.assertEquals("YubiKit for Android test data", s);
  }

  @Test
  public void decompressCertificateNetIdZlib() throws Throwable {
    String s = new String(decompressCertificate(netIdZlibTestData), StandardCharsets.ISO_8859_1);
    Assert.assertEquals("YubiKit for Android test data", s);
  }

  @Test(expected = IOException.class)
  public void decompressCertificateUnknownFormat() throws Throwable {
    decompressCertificate(new byte[] {0x02, 0x03, 0x04, 0x05});
  }

  @Test(expected = IOException.class)
  public void decompressCertificateTooShort() throws Throwable {
    decompressCertificate(new byte[] {0x01});
  }
}

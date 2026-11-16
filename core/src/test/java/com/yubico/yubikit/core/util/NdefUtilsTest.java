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
package com.yubico.yubikit.core.util;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.Assert;
import org.junit.Test;

public class NdefUtilsTest {
  private static final String OTP = "cccccccccccbhkbtnilebckgkbiruftdnbdclgbiunfkr";

  /** Builds a short NDEF URI record for https://{url} with the given payload length byte. */
  private static byte[] record(int payloadLength, String url) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0xd1);
    out.write(0x01);
    out.write(payloadLength);
    out.write(0x55);
    out.write(0x04);
    byte[] urlBytes = url.getBytes(StandardCharsets.UTF_8);
    out.write(urlBytes, 0, urlBytes.length);
    return out.toByteArray();
  }

  /** Builds a record whose payload length byte matches the URL. */
  private static byte[] record(String url) {
    return record(1 + url.getBytes(StandardCharsets.UTF_8).length, url);
  }

  private static void assertInvalid(byte[] ndefData) {
    Assert.assertThrows(
        IllegalArgumentException.class, () -> NdefUtils.getNdefPayloadBytes(ndefData));
  }

  @Test
  public void testFragmentPayload() {
    Assert.assertEquals(OTP, NdefUtils.getNdefPayload(record("my.yubico.com/yk/#" + OTP)));
  }

  @Test
  public void testNeoPayload() {
    Assert.assertEquals(OTP, NdefUtils.getNdefPayload(record("my.yubico.com/neo/" + OTP)));
  }

  @Test
  public void testPayloadLengthAbove127() {
    char[] filler = new char[150];
    Arrays.fill(filler, 'c');
    String otp = new String(filler);
    byte[] data = record("my.yubico.com/yk/#" + otp);
    Assert.assertTrue((data[2] & 0xff) > 0x7f);
    Assert.assertEquals(otp, NdefUtils.getNdefPayload(data));
  }

  @Test
  public void testTrailingBytesIgnored() {
    String url = "my.yubico.com/yk/#" + OTP;
    byte[] data = record(1 + url.length(), url + "trailing");
    Assert.assertEquals(OTP, NdefUtils.getNdefPayload(data));
  }

  @Test
  public void testWrongHeader() {
    byte[] data = record("my.yubico.com/yk/#" + OTP);
    data[3] = 0x54; // text record
    assertInvalid(data);
  }

  @Test
  public void testWrongDomain() {
    assertInvalid(record("my.yubica.com/yk/#" + OTP));
  }

  @Test
  public void testMissingFragment() {
    assertInvalid(record("my.yubico.com/yk/" + OTP));
  }

  @Test
  public void testTruncatedHeader() {
    byte[] data = record("my.yubico.com/yk/#" + OTP);
    for (int length = 0; length < 5; length++) {
      assertInvalid(Arrays.copyOf(data, length));
    }
  }

  @Test
  public void testTruncatedDomain() {
    byte[] data = record("my.yubico.com/yk/#" + OTP);
    assertInvalid(Arrays.copyOf(data, 10));
  }

  @Test
  public void testPayloadLongerThanData() {
    String url = "my.yubico.com/yk/#" + OTP;
    assertInvalid(record(2 + url.length(), url));
    assertInvalid(record(0xff, url));
  }

  @Test
  public void testPayloadLengthZero() {
    // (0 - typeLength) is negative; masking the subtraction yields 255 instead
    assertInvalid(record(0, "my.yubico.com/yk/#" + OTP));
  }

  @Test
  public void testPayloadShorterThanDomain() {
    assertInvalid(record(1 + 5, "my.yubico.com/yk/#" + OTP));
    assertInvalid(record(1, "my.yubico.com/yk/#" + OTP));
  }
}

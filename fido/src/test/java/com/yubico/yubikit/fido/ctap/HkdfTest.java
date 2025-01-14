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

package com.yubico.yubikit.fido.ctap;

import com.yubico.yubikit.testing.Codec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import org.junit.Assert;
import org.junit.Test;

@SuppressWarnings("SpellCheckingInspection")
public class HkdfTest {
  @Test
  public void testCase1() throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] okm =
        new Hkdf("HmacSHA256")
            .digest(
                Codec.fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                Codec.fromHex("000102030405060708090a0b0c"),
                Codec.fromHex("f0f1f2f3f4f5f6f7f8f9"),
                42);

    Assert.assertArrayEquals(
        Codec.fromHex(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
        okm);
  }

  @Test
  public void testCase2() throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] okm =
        new Hkdf("HmacSHA256")
            .digest(
                Codec.fromHex(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252"
                        + "62728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849"
                        + "4a4b4c4d4e4f"),
                Codec.fromHex(
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858"
                        + "68788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9"
                        + "aaabacadaeaf"),
                Codec.fromHex(
                    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d"
                        + "6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9"
                        + "fafbfcfdfeff"),
                82);
    Assert.assertArrayEquals(
        Codec.fromHex(
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb4"
                + "1c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87"),
        okm);
  }

  @Test
  public void testCase3() throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] okm =
        new Hkdf("HmacSHA256")
            .digest(
                Codec.fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                new byte[0],
                new byte[0],
                42);

    Assert.assertArrayEquals(
        Codec.fromHex(
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
        okm);
  }

  @Test
  public void testCase4() throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] okm =
        new Hkdf("HmacSHA1")
            .digest(
                Codec.fromHex("0b0b0b0b0b0b0b0b0b0b0b"),
                Codec.fromHex("000102030405060708090a0b0c"),
                Codec.fromHex("f0f1f2f3f4f5f6f7f8f9"),
                42);

    Assert.assertArrayEquals(
        Codec.fromHex(
            "085a01ea1b10f36933068b56efa5ad81a4f14b822f5b091568a9cdd4f155fda2c22e422478d305f3f896"),
        okm);
  }

  @Test
  public void testCase5() throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] okm =
        new Hkdf("HmacSHA1")
            .digest(
                Codec.fromHex(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021222324252"
                        + "62728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849"
                        + "4a4b4c4d4e4f"),
                Codec.fromHex(
                    "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858"
                        + "68788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9"
                        + "aaabacadaeaf"),
                Codec.fromHex(
                    "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d"
                        + "6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9"
                        + "fafbfcfdfeff"),
                82);

    Assert.assertArrayEquals(
        Codec.fromHex(
            "0bd770a74d1160f7c9f12cd5912a06ebff6adcae899d92191fe4305673ba2ffe8fa3f1a4e5ad79f3f334b"
                + "3b202b2173c486ea37ce3d397ed034c7f9dfeb15c5e927336d0441f4c4300e2cff0d0900b52d3b4"),
        okm);
  }

  @Test
  public void testCase6() throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] okm =
        new Hkdf("HmacSHA1")
            .digest(
                Codec.fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"),
                new byte[0],
                new byte[0],
                42);

    Assert.assertArrayEquals(
        Codec.fromHex(
            "0ac1af7002b3d761d1e55298da9d0506b9ae52057220a306e07b6b87e8df21d0ea00033de03984d34918"),
        okm);
  }

  @Test
  public void testCase7() throws NoSuchAlgorithmException, InvalidKeyException {
    byte[] okm =
        new Hkdf("HmacSHA1")
            .digest(
                Codec.fromHex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c"),
                new byte[0],
                new byte[0],
                42);

    Assert.assertArrayEquals(
        Codec.fromHex(
            "2c91117204d745f3500d636a62f64f0ab3bae548aa53d423b0d1f27ebba6f5e5673a081d70cce7acfc48"),
        okm);
  }
}

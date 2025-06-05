/*
 * Copyright (C) 2020-2023 Yubico.
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

import com.yubico.yubikit.fido.TestUtils;
import java.math.BigInteger;
import org.junit.Assert;
import org.junit.Test;

public class PinUvAuthProtocolV1Test {
  private final PinUvAuthProtocolV1 protocol = new PinUvAuthProtocolV1();

  @Test
  public void testEncrypt() {
    byte[] pinToken = TestUtils.decodeHex("000102030405060708090a0b0c0d0e0f");

    Assert.assertArrayEquals(
        TestUtils.decodeHex("0a940bb5416ef045f1c39458c653ea5a"),
        protocol.encrypt(pinToken, TestUtils.decodeHex("000102030405060708090a0b0c0d0e0f")));

    Assert.assertArrayEquals(
        TestUtils.decodeHex("c6a13b37878f5b826f4f8162a1c8d879"),
        protocol.encrypt(pinToken, TestUtils.decodeHex("00000000000000000000000000000000")));
  }

  @Test
  public void testDecrypt() {
    byte[] pinToken = TestUtils.decodeHex("000102030405060708090a0b0c0d0e0f");

    Assert.assertArrayEquals(
        TestUtils.decodeHex("000102030405060708090a0b0c0d0e0f"),
        protocol.decrypt(pinToken, TestUtils.decodeHex("0a940bb5416ef045f1c39458c653ea5a")));

    Assert.assertArrayEquals(
        TestUtils.decodeHex("00000000000000000000000000000000"),
        protocol.decrypt(pinToken, TestUtils.decodeHex("c6a13b37878f5b826f4f8162a1c8d879")));
  }

  @Test
  public void testAuthenticate() {
    byte[] pinToken = TestUtils.decodeHex("000102030405060708090a0b0c0d0e0f");

    Assert.assertArrayEquals(
        TestUtils.decodeHex("9f3aa28826b37485ca05014d7142b3ea"),
        protocol.authenticate(pinToken, TestUtils.decodeHex("000102030405060708090a0b0c0d0e0f")));

    Assert.assertArrayEquals(
        TestUtils.decodeHex("fe6e8016f7f241c07565b467688e20c7"),
        protocol.authenticate(pinToken, TestUtils.decodeHex("00000000000000000000000000000000")));
  }

  @Test
  public void testEncodeCoordinate() {
    Assert.assertArrayEquals(
        TestUtils.decodeHex("0000000000000000000000000000000000000000000000000000000000000001"),
        PinUvAuthProtocolV1.encodeCoordinate(new BigInteger("1")));

    Assert.assertArrayEquals(
        TestUtils.decodeHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        PinUvAuthProtocolV1.encodeCoordinate(
            new BigInteger(
                "115792089237316195423570985008687907853269984665640564039457584007913129639935")));

    Assert.assertArrayEquals(
        TestUtils.decodeHex("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        PinUvAuthProtocolV1.encodeCoordinate(
            new BigInteger(
                "57896044618658097711785492504343953926634992332820282019728792003956564819967")));

    Assert.assertArrayEquals(
        TestUtils.decodeHex("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        PinUvAuthProtocolV1.encodeCoordinate(
            new BigInteger(
                "904625697166532776746648320380374280103671755200316906558262375061821325311")));

    Assert.assertArrayEquals(
        TestUtils.decodeHex("00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        PinUvAuthProtocolV1.encodeCoordinate(
            new BigInteger(
                "452312848583266388373324160190187140051835877600158453279131187530910662655")));

    Assert.assertArrayEquals(
        TestUtils.decodeHex("007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        PinUvAuthProtocolV1.encodeCoordinate(
            new BigInteger(
                "226156424291633194186662080095093570025917938800079226639565593765455331327")));
  }
}

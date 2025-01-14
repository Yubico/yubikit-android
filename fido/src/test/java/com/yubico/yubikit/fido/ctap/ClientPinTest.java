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

import static com.yubico.yubikit.fido.TestUtils.decodeHex;

import java.util.Arrays;
import org.junit.Assert;
import org.junit.Test;

public class ClientPinTest {
  @Test
  public void testPadPin() {
    Assert.assertArrayEquals(
        decodeHex("31323334"), ClientPin.preparePin("1234".toCharArray(), false));
    Assert.assertArrayEquals(
        Arrays.copyOf(decodeHex("31323334"), 64), ClientPin.preparePin("1234".toCharArray(), true));
    Assert.assertArrayEquals(
        decodeHex("666f6f626172"), ClientPin.preparePin("foobar".toCharArray(), false));
    Assert.assertArrayEquals(
        Arrays.copyOf(decodeHex("666f6f626172"), 64),
        ClientPin.preparePin("foobar".toCharArray(), true));
    Assert.assertEquals(
        64,
        ClientPin.preparePin(
                "123456789012345678901234567890123456789012345678901234567890123".toCharArray(),
                true)
            .length);
    Assert.assertEquals(
        63,
        ClientPin.preparePin(
                "123456789012345678901234567890123456789012345678901234567890123".toCharArray(),
                false)
            .length);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testTooShortPin() {
    ClientPin.preparePin("123".toCharArray(), false);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testTooShortPinWithPad() {
    ClientPin.preparePin("123".toCharArray(), true);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testTooLongPin() {
    ClientPin.preparePin(
        "1234567890123456789012345678901234567890123456789012345678901234".toCharArray(), false);
  }

  @Test(expected = IllegalArgumentException.class)
  public void testTooLongPinWithPad() {
    ClientPin.preparePin(
        "1234567890123456789012345678901234567890123456789012345678901234".toCharArray(), true);
  }
}

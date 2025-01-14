/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.oath;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.yubico.yubikit.testing.Codec;
import org.junit.Test;

@SuppressWarnings("SpellCheckingInspection")
public class Base32Test {

  @Test
  public void testValidInput() {
    assertTrue(Base32.isValid(""));
    assertTrue(Base32.isValid("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"));
    assertTrue(Base32.isValid("AA======"));
    assertTrue(Base32.isValid("MZXQ===="));
    assertTrue(Base32.isValid("AA"));
    assertTrue(Base32.isValid("AAAA"));
    assertTrue(Base32.isValid("AAAAA"));
    assertTrue(Base32.isValid("AAAAAAA"));
  }

  @Test
  public void testInvalidInput() {
    assertFalse(Base32.isValid("0189"));
    assertFalse(Base32.isValid(";.*"));
    assertFalse(Base32.isValid("😀"));
    assertFalse(Base32.isValid("abcdefghijklmnopqrstuvwxyz234567"));
    assertFalse(Base32.isValid("AA="));
    assertFalse(Base32.isValid("AA=="));
    assertFalse(Base32.isValid("AA==="));
    assertFalse(Base32.isValid("AA===="));
    assertFalse(Base32.isValid("AA====="));
    assertFalse(Base32.isValid("AA======="));
    assertFalse(Base32.isValid("A"));
    assertFalse(Base32.isValid("AAA"));
    assertFalse(Base32.isValid("AAAAAA"));
    assertFalse(Base32.isValid("="));
    assertFalse(Base32.isValid("=="));
    assertFalse(Base32.isValid("==="));
    assertFalse(Base32.isValid("AAAAAAA=A"));
    assertFalse(Base32.isValid("MZ=XW6YTB"));
    assertFalse(Base32.isValid("MZXQ=="));
  }

  @Test
  public void testEncode() {
    assertEquals("", Base32.encode("".getBytes()));
    assertEquals("MY======", Base32.encode("f".getBytes()));
    assertEquals("MZXQ====", Base32.encode("fo".getBytes()));
    assertEquals("MZXW6===", Base32.encode("foo".getBytes()));
    assertEquals("MZXW6YQ=", Base32.encode("foob".getBytes()));
    assertEquals("MZXW6YTB", Base32.encode("fooba".getBytes()));
    assertEquals("MZXW6YTBOI======", Base32.encode("foobar".getBytes()));
    assertEquals(
        "PF2WE2LLNF2C243ENMQDELSYFYYCAIBAEE======",
        Base32.encode("yubikit-sdk 2.X.0   !".getBytes()));
    assertEquals(
        "KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWOLQ=",
        Base32.encode("The quick brown fox jumps over the lazy dog.".getBytes()));
    assertEquals("WZEBZC7I6IQXTNMK", Base32.encode(Codec.fromHex("b6481c8be8f22179b58a")));
    assertEquals(
        "NG3EQHELVORLMDUPEILZWWGNKY======",
        Base32.encode(Codec.fromHex("69b6481c8baba2b60e8f22179b58cd56")));
  }

  @Test
  public void testDecode() {
    assertArrayEquals("f".getBytes(), Base32.decode("MY======"));
    assertArrayEquals("fo".getBytes(), Base32.decode("MZXQ===="));
    assertArrayEquals("foo".getBytes(), Base32.decode("MZXW6==="));
    assertArrayEquals("foob".getBytes(), Base32.decode("MZXW6YQ="));
    assertArrayEquals("fooba".getBytes(), Base32.decode("MZXW6YTB"));
    assertArrayEquals("foobar".getBytes(), Base32.decode("MZXW6YTBOI======"));
    assertArrayEquals(
        "yubikit-sdk 2.X.0   !".getBytes(),
        Base32.decode("PF2WE2LLNF2C243ENMQDELSYFYYCAIBAEE======"));
    assertArrayEquals(
        "The quick brown fox jumps over the lazy dog.".getBytes(),
        Base32.decode("KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWOLQ="));
    assertArrayEquals(
        Codec.fromHex("69b6481c8baba2b60e8f22179b58cd56"),
        Base32.decode("NG3EQHELVORLMDUPEILZWWGNKY======"));
  }

  @Test
  public void testDecodeWithoutPadding() {
    assertArrayEquals("".getBytes(), Base32.decode(""));
    assertArrayEquals("f".getBytes(), Base32.decode("MY"));
    assertArrayEquals("fo".getBytes(), Base32.decode("MZXQ"));
    assertArrayEquals("foo".getBytes(), Base32.decode("MZXW6"));
    assertArrayEquals("foob".getBytes(), Base32.decode("MZXW6YQ"));
    assertArrayEquals("fooba".getBytes(), Base32.decode("MZXW6YTB"));
    assertArrayEquals("foobar".getBytes(), Base32.decode("MZXW6YTBOI"));
    assertArrayEquals(
        "yubikit-sdk 2.X.0   !".getBytes(), Base32.decode("PF2WE2LLNF2C243ENMQDELSYFYYCAIBAEE"));
    assertArrayEquals(
        "The quick brown fox jumps over the lazy dog.".getBytes(),
        Base32.decode("KRUGKIDROVUWG2ZAMJZG653OEBTG66BANJ2W24DTEBXXMZLSEB2GQZJANRQXU6JAMRXWOLQ"));
    assertArrayEquals(Codec.fromHex("b6481c8be8f22179b58a"), Base32.decode("WZEBZC7I6IQXTNMK"));
  }

  @Test
  public void testDecodeThrows() {
    byte[] invalid = new byte[] {0};

    try {
      assertArrayEquals(invalid, Base32.decode("invalidinput"));
      fail();
    } catch (IllegalArgumentException ignored) {
    }

    try {
      assertArrayEquals(invalid, Base32.decode("M="));
      fail();
    } catch (IllegalArgumentException ignored) {
    }

    try {
      assertArrayEquals(invalid, Base32.decode("A=A"));
      fail();
    } catch (IllegalArgumentException ignored) {
    }

    try {
      assertArrayEquals(invalid, Base32.decode("="));
      fail();
    } catch (IllegalArgumentException ignored) {
    }

    try {
      assertArrayEquals(invalid, Base32.decode("MZXQ=="));
      fail();
    } catch (IllegalArgumentException ignored) {
    }

    try {
      assertArrayEquals(invalid, Base32.decode("A"));
      fail();
    } catch (IllegalArgumentException ignored) {
    }

    try {
      assertArrayEquals(invalid, Base32.decode("AAA"));
      fail();
    } catch (IllegalArgumentException ignored) {
    }

    try {
      assertArrayEquals(invalid, Base32.decode("AAAAAA"));
      fail();
    } catch (IllegalArgumentException ignored) {
    }
  }
}

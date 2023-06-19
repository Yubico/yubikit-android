/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.ctap;

import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;

import static com.yubico.yubikit.fido.TestUtils.decodeHex;

public class ClientPinTest {
    @Test
    public void testPadPin() {
        Assert.assertArrayEquals(decodeHex("31323334"), ClientPin.preparePin("1234".toCharArray(), false));
        Assert.assertArrayEquals(Arrays.copyOf(decodeHex("31323334"), 64), ClientPin.preparePin("1234".toCharArray(), true));
        Assert.assertArrayEquals(decodeHex("666f6f626172"), ClientPin.preparePin("foobar".toCharArray(), false));
        Assert.assertArrayEquals(Arrays.copyOf(decodeHex("666f6f626172"), 64), ClientPin.preparePin("foobar".toCharArray(), true));
        Assert.assertEquals(64, ClientPin.preparePin("123456789012345678901234567890123456789012345678901234567890123".toCharArray(), true).length);
        Assert.assertEquals(63, ClientPin.preparePin("123456789012345678901234567890123456789012345678901234567890123".toCharArray(), false).length);
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
        ClientPin.preparePin("1234567890123456789012345678901234567890123456789012345678901234".toCharArray(), false);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testTooLongPinWithPad() {
        ClientPin.preparePin("1234567890123456789012345678901234567890123456789012345678901234".toCharArray(), true);
    }
}

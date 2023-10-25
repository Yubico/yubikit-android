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

import org.junit.Assert;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class PinUvAuthProtocolV2Test {
    private final PinUvAuthProtocolV2 protocol = new PinUvAuthProtocolV2();

    @Test
    public void testEncryptDecrypt() {
        byte[] pinToken = ByteBuffer.allocate(64)
                .position(32)
                .put(TestUtils.decodeHex(
                        "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f"))
                .array();

        byte[] ciphertext = protocol.encrypt(
                pinToken,
                TestUtils.decodeHex("000102030405060708090a0b0c0d0e0f")
        );

        Assert.assertEquals(32, ciphertext.length);

        byte[] plaintext = protocol.decrypt(pinToken, ciphertext);
        Assert.assertArrayEquals(
                TestUtils.decodeHex("000102030405060708090a0b0c0d0e0f"),
                plaintext);

        ciphertext = protocol.encrypt(
                pinToken,
                TestUtils.decodeHex("00000000000000000000000000000000")
        );

        Assert.assertEquals(32, ciphertext.length);

        plaintext = protocol.decrypt(pinToken, ciphertext);
        Assert.assertArrayEquals(
                TestUtils.decodeHex("00000000000000000000000000000000"),
                plaintext);
    }

    @Test
    public void testAuthenticate() {
        byte[] pinToken = TestUtils.decodeHex(
                "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f");

        Assert.assertArrayEquals(
                TestUtils.decodeHex(
                        "495d46aa392d51132edb93bc49e60ecaaeb7802f3ae529779d5883f9330af561"),
                protocol.authenticate(
                        pinToken,
                        TestUtils.decodeHex("000102030405060708090a0b0c0d0e0f"))
        );

        Assert.assertArrayEquals(
                TestUtils.decodeHex(
                        "7f0ea2b80504890f3c6d42a77e31c833e881f741d2125569ac6427aa0c466aad"),
                protocol.authenticate(
                        pinToken,
                        TestUtils.decodeHex("00000000000000000000000000000000"))
        );
    }

    @Test
    public void testEncodeCoordinate() {
        Assert.assertArrayEquals(
                TestUtils.decodeHex(
                        "0000000000000000000000000000000000000000000000000000000000000001"),
                PinUvAuthProtocolV2.encodeCoordinate(new BigInteger("1"))
        );

        Assert.assertArrayEquals(
                TestUtils.decodeHex(
                        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                PinUvAuthProtocolV2.encodeCoordinate(
                        new BigInteger("11579208923731619542357098500868790785326998466564056" +
                                "4039457584007913129639935"))
        );

        Assert.assertArrayEquals(
                TestUtils.decodeHex(
                        "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                PinUvAuthProtocolV2.encodeCoordinate(
                        new BigInteger("57896044618658097711785492504343953926634992332820282" +
                                "019728792003956564819967"))
        );

        Assert.assertArrayEquals(
                TestUtils.decodeHex(
                        "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                PinUvAuthProtocolV2.encodeCoordinate(
                        new BigInteger("90462569716653277674664832038037428010367175520031690" +
                                "6558262375061821325311"))
        );

        Assert.assertArrayEquals(
                TestUtils.decodeHex(
                        "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                PinUvAuthProtocolV2.encodeCoordinate(
                        new BigInteger("45231284858326638837332416019018714005183587760015845" +
                                "3279131187530910662655"))
        );

        Assert.assertArrayEquals(
                TestUtils.decodeHex(
                        "007fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
                PinUvAuthProtocolV2.encodeCoordinate(new BigInteger("226156424291633194186662" +
                        "080095093570025917938800079226639565593765455331327"))
        );
    }
}

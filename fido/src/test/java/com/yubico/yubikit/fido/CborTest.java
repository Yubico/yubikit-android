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

package com.yubico.yubikit.fido;

import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.yubico.yubikit.fido.TestUtils.decodeHex;
import static com.yubico.yubikit.fido.TestUtils.encodeHex;

public class CborTest {

    private static Object wrapInt(Object value) {
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return value;
    }

    private static Map<Object, Object> mapOf(Object... items) {
        Map<Object, Object> map = new HashMap<>();
        for (int i = 0; i < items.length; i += 2) {
            map.put(wrapInt(items[i]), wrapInt(items[i + 1]));
        }
        return map;
    }

    private static List<Object> listOf(Object... items) {
        List<Object> list = new ArrayList<>();
        for (Object item : items) {
            list.add(wrapInt(item));
        }
        return list;
    }

    private static void assertCborEncode(String expectedHex, Object value) {
        byte[] encoded = Cbor.encode(value);
        Assert.assertArrayEquals(
                String.format("Expected to encode to %s, but got %s", expectedHex, encodeHex(encoded)),
                decodeHex(expectedHex),
                encoded
        );
    }

    private static void assertCborDecode(Object expected, String cborHex) {
        Object actual = Cbor.decode(decodeHex(cborHex));
        if (expected instanceof byte[]) {
            byte[] expectBytes = (byte[]) expected;
            byte[] actualBytes = (byte[]) actual;
            Assert.assertArrayEquals(
                    String.format("Expected to decode into %s, but got %s", encodeHex(expectBytes), encodeHex(actualBytes)),
                    expectBytes,
                    actualBytes
            );
        } else {
            Assert.assertEquals(
                    String.format("Expected to decode into %s, but got %s", expected, actual),
                    wrapInt(expected),
                    actual
            );
        }
    }

    private static void assertCborEncodeAndDecode(String expectedHex, Object value) {
        assertCborEncode(expectedHex, value);
        assertCborDecode(value, expectedHex);
    }

    private static final class TestData {
        private final String cborHex;
        private final Object value;

        private TestData(String cborHex, Object value) {
            this.cborHex = cborHex;
            this.value = value;
        }
    }

    private static final List<TestData> TEST_VECTORS = Arrays.asList(
            new TestData("00", 0),
            new TestData("01", 1),
            new TestData("0a", 10),
            new TestData("17", 23),
            new TestData("1818", 24),
            new TestData("1819", 25),
            new TestData("1864", 100),
            new TestData("1903e8", 1000),
            new TestData("1a000f4240", 1000000),
            // new TestData("1b000000e8d4a51000", 1000000000000L),
            // new TestData("1bffffffffffffffff", 18446744073709551615),
            // ('c249010000000000000000', 18446744073709551616),
            // new TestData("3bffffffffffffffff", -18446744073709551616),
            // ('c349010000000000000000', -18446744073709551617),
            new TestData("20", -1),
            new TestData("29", -10),
            new TestData("3863", -100),
            new TestData("3903e7", -1000),
            // ('f90000', 0.0),
            // ('f98000', -0.0),
            // ('f93c00', 1.0),
            // ('fb3ff199999999999a', 1.1),
            // ('f93e00', 1.5),
            // ('f97bff', 65504.0),
            // ('fa47c35000', 100000.0),
            // ('fa7f7fffff', 3.4028234663852886e+38),
            // ('fb7e37e43c8800759c', 1e+300),
            // ('f90001', 5.960464477539063e-08),
            // ('f90400', 6.103515625e-05),
            // ('f9c400', -4.0),
            // ('fbc010666666666666', -4.1),
            // ('f97c00', None),
            // ('f97e00', None),
            // ('f9fc00', None),
            // ('fa7f800000', None),
            // ('fa7fc00000', None),
            // ('faff800000', None),
            // ('fb7ff0000000000000', None),
            // ('fb7ff8000000000000', None),
            // ('fbfff0000000000000', None),
            new TestData("f4", false),
            new TestData("f5", true),
            // ('f6', None),
            // ('f7', None),
            // ('f0', None),
            // ('f818', None),
            // ('f8ff', None),
            // ('c074323031332d30332d32315432303a30343a30305a', None),
            // ('c11a514b67b0', None),
            // ('c1fb41d452d9ec200000', None),
            // ('d74401020304', None),
            // ('d818456449455446', None),
            // ('d82076687474703a2f2f7777772e6578616d706c652e636f6d', None),
            new TestData("40", new byte[0]),
            new TestData("4401020304", new byte[]{1, 2, 3, 4}),
            new TestData("60", ""),
            new TestData("6161", "a"),
            new TestData("6449455446", "IETF"),
            new TestData("62225c", "\"\\"),
            new TestData("62c3bc", "ü"),
            new TestData("63e6b0b4", "水"),
            new TestData("64f0908591", "\ud800\udd51"),
            new TestData("80", listOf()),
            new TestData("83010203", listOf(1, 2, 3)),
            new TestData("8301820203820405", listOf(1, listOf(2, 3), listOf(4, 5))),
            new TestData(
                    "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
                    listOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25)
            ),
            new TestData("a0", mapOf()),
            new TestData("a201020304", mapOf(1, 2, 3, 4)),
            new TestData("a26161016162820203", mapOf("a", 1, "b", listOf(2, 3))),
            new TestData("826161a161626163", listOf("a", mapOf("b", "c"))),
            new TestData(
                    "a56161614161626142616361436164614461656145",
                    mapOf("c", "C", "d", "D", "a", "A", "b", "B", "e", "E")
            )
            // ('5f42010243030405ff', None),
            // ('7f657374726561646d696e67ff', 'streaming'),
            // ('9fff', []),
            // ('9f018202039f0405ffff', [1, [2, 3], [4, 5]]),
            // ('9f01820203820405ff', [1, [2, 3], [4, 5]]),
            // ('83018202039f0405ff', [1, [2, 3], [4, 5]]),
            // ('83019f0203ff820405', [1, [2, 3], [4, 5]]),
            // ('9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff', [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25]),  // noqa E501
            // ('bf61610161629f0203ffff', {'a': 1, 'b': [2, 3]}),
            // ('826161bf61626163ff', ['a', {'b': 'c'}]),
            // ('bf6346756ef563416d7421ff', {'Amt': -2, 'Fun': True}),
    );


    @Test
    public void testVectors() {
        for (TestData pair : TEST_VECTORS) {
            assertCborEncodeAndDecode(pair.cborHex, pair.value);
        }
    }

    @Test
    public void testIntegers() {
        assertCborEncodeAndDecode("00", 0);
        assertCborEncodeAndDecode("17", 23);
        assertCborEncodeAndDecode("1818", 24);
        assertCborEncodeAndDecode("18ff", 255);
        assertCborEncodeAndDecode("190100", 256);
        assertCborEncodeAndDecode("19ffff", 65535);
        assertCborEncodeAndDecode("1a00010000", 65536);
        assertCborEncodeAndDecode("1a7fffffff", Integer.MAX_VALUE);
        //assertCborEncodeAndDecode("1affffffff", 4294967295L);
        //assertCborEncodeAndDecode("1b7fffffffffffffff", Long.MAX_VALUE);

        assertCborEncodeAndDecode("20", -1);
        assertCborEncodeAndDecode("37", -24);
        assertCborEncodeAndDecode("3818", -25);
        assertCborEncodeAndDecode("3a7fffffff", Integer.MIN_VALUE);
        //assertCborEncodeAndDecode("3affffffff", -4294967296L);
        //assertCborEncodeAndDecode("3b7fffffffffffffff", Long.MIN_VALUE);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testDecodeIntOutOfRange() {
        Cbor.decode(decodeHex("1a80000000"));
    }

    @Test
    public void testKeyOrder() {
        assertCborEncode("a30100413200613300", mapOf("3", 0, "2".getBytes(), 0, 1, 0));
        assertCborEncode("a3190100004000613300", mapOf("3", 0, "".getBytes(), 0, 256, 0));
        assertCborEncode("a4000018ff00190100001a7fffffff00", mapOf(Integer.MAX_VALUE, 0, 255, 0, 256, 0, 0, 0));
        assertCborEncode("a3413300423232004331313100", mapOf("22".getBytes(), 0, "3".getBytes(), 0, "111".getBytes(), 0));
        assertCborEncode("a3433030310043303032004330303300", mapOf("001".getBytes(), 0, "003".getBytes(), 0, "002".getBytes(), 0));
        assertCborEncode("a2f400f500", mapOf(true, 0, false, 0));
        assertCborEncode("a3613100623130006331303000", mapOf("1", 0, "100", 0, "10", 0));
    }
}

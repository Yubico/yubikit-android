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

import static com.yubico.yubikit.fido.TestUtils.decodeHex;
import static com.yubico.yubikit.fido.TestUtils.encodeHex;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

/** Unit tests for cbor functionality implemented in {@code Cbor} class. */
@RunWith(Enclosed.class)
public class CborTest {
  /**
   * Superclass for cbor parametrized tests.
   *
   * <p>Subclasses need to be annotated with {@code @RunWith(Parameterized.class)} and implement one
   * or more {@code @Test} methods and return test data through {@code @Parameters data()}
   */
  private static class ParametrizedCborTest {

    @SuppressWarnings("NotNullFieldNotInitialized")
    @Parameter
    public String cborHex;

    @SuppressWarnings("NotNullFieldNotInitialized")
    @Parameter(1)
    public Object value;
  }

  /** Tests encoding and decoding of integer types */
  @RunWith(Parameterized.class)
  public static class IntegerTest extends ParametrizedCborTest {
    @Parameters
    public static Collection<Object[]> data() {
      return Arrays.asList(
          new Object[][] {
            {"00", 0},
            {"01", 1},
            {"0a", 10},
            {"17", 23},
            {"1818", 24},
            {"1819", 25},
            {"1864", 100},
            {"1903e8", 1000},
            {"1a000f4240", 1000000},
            {"19ffff", 65535},
            {"1a00010000", 65536},
            {"1a7fffffff", Integer.MAX_VALUE},
            {"20", -1},
            {"29", -10},
            {"37", -24},
            {"3818", -25},
            {"3863", -100},
            {"3903e7", -1000},
            {"3a7fffffff", Integer.MIN_VALUE},
          });
    }

    @Test
    public void testInteger() {
      assertCborEncodeAndDecode(cborHex, value);
    }
  }

  /** Tests encoding and decoding of simple boolean values */
  @RunWith(Parameterized.class)
  public static class SimpleBooleanTest extends ParametrizedCborTest {
    @Parameters
    public static Collection<Object[]> data() {
      return Arrays.asList(
          new Object[][] {
            {"f4", false},
            {"f5", true},
          });
    }

    @Test
    public void testSimpleBoolean() {
      assertCborEncodeAndDecode(cborHex, value);
    }
  }

  /** Tests encoding and decoding of byte array values */
  @RunWith(Parameterized.class)
  public static class ByteArrayTest extends ParametrizedCborTest {
    @Parameters
    public static Collection<Object[]> data() {
      return Arrays.asList(
          new Object[][] {
            {"40", new byte[0]},
            {"4401020304", new byte[] {1, 2, 3, 4}},
          });
    }

    @Test
    public void testByteArray() {
      assertCborEncodeAndDecode(cborHex, value);
    }
  }

  /** Tests encoding and decoding of String values */
  @RunWith(Parameterized.class)
  public static class StringTest extends ParametrizedCborTest {
    @Parameters
    public static Collection<Object[]> data() {
      return Arrays.asList(
          new Object[][] {
            {"40", new byte[0]},
            {"4401020304", new byte[] {1, 2, 3, 4}},
            {"60", ""},
            {"6161", "a"},
            {"6449455446", "IETF"},
            {"62225c", "\"\\"},
            {"62c3bc", "ü"},
            {"63e6b0b4", "水"},
            {"64f0908591", "\ud800\udd51"},
          });
    }

    @Test
    public void testString() {
      assertCborEncodeAndDecode(cborHex, value);
    }
  }

  /** Tests encoding and decoding of Lists */
  @RunWith(Parameterized.class)
  public static class ListTest extends ParametrizedCborTest {
    @Parameters
    public static Collection<Object[]> data() {
      return Arrays.asList(
          new Object[][] {
            {"80", listOf()},
            {"83010203", listOf(1, 2, 3)},
            {"8301820203820405", listOf(1, listOf(2, 3), listOf(4, 5))},
            {
              "98190102030405060708090a0b0c0d0e0f101112131415161718181819",
              listOf(
                  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                  24, 25)
            },
          });
    }

    @Test
    public void testList() {
      assertCborEncodeAndDecode(cborHex, value);
    }
  }

  /** Tests encoding and decoding of Maps */
  @RunWith(Parameterized.class)
  public static class MapTest extends ParametrizedCborTest {
    @Parameters
    public static Collection<Object[]> data() {
      return Arrays.asList(
          new Object[][] {
            {"a0", mapOf()},
            {"a201020304", mapOf(1, 2, 3, 4)},
            {"a26161016162820203", mapOf("a", 1, "b", listOf(2, 3))},
            {"826161a161626163", listOf("a", mapOf("b", "c"))},
            {
              "a56161614161626142616361436164614461656145",
              mapOf("c", "C", "d", "D", "a", "A", "b", "B", "e", "E")
            },
          });
    }

    @Test
    public void testMap() {
      assertCborEncodeAndDecode(cborHex, value);
    }
  }

  /** Tests order of keys */
  @RunWith(Parameterized.class)
  public static class KeyOrderTest extends ParametrizedCborTest {
    @Parameters
    public static Collection<Object[]> data() {
      return Arrays.asList(
          new Object[][] {
            {"a30100413200613300", mapOf("3", 0, "2".getBytes(), 0, 1, 0)},
            {"a3190100004000613300", mapOf("3", 0, "".getBytes(), 0, 256, 0)},
            {"a4000018ff00190100001a7fffffff00", mapOf(Integer.MAX_VALUE, 0, 255, 0, 256, 0, 0, 0)},
            {
              "a3413300423232004331313100",
              mapOf("22".getBytes(), 0, "3".getBytes(), 0, "111".getBytes(), 0)
            },
            {
              "a3433030310043303032004330303300",
              mapOf("001".getBytes(), 0, "003".getBytes(), 0, "002".getBytes(), 0)
            },
            {"a2f400f500", mapOf(true, 0, false, 0)},
            {"a3613100623130006331303000", mapOf("1", 0, "100", 0, "10", 0)}
          });
    }

    @Test
    public void testKeyOrder() {
      assertCborEncode(cborHex, value);
    }
  }

  public static class OtherTests {
    @Test(expected = IllegalArgumentException.class)
    public void testDecodeIntOutOfRange() {
      Cbor.decode(decodeHex("1a80000000"));
    }
  }

  // helper methods
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
        encoded);
  }

  private static void assertCborDecode(Object expected, String cborHex) {
    Object actual = Cbor.decode(decodeHex(cborHex));
    if (expected instanceof byte[]) {
      byte[] expectBytes = (byte[]) expected;
      byte[] actualBytes = (byte[]) actual;
      Assert.assertNotNull(actualBytes);
      Assert.assertArrayEquals(
          String.format(
              "Expected to decode into %s, but got %s",
              encodeHex(expectBytes), encodeHex(actualBytes)),
          expectBytes,
          actualBytes);
    } else {
      Assert.assertEquals(
          String.format("Expected to decode into %s, but got %s", expected, actual),
          wrapInt(expected),
          actual);
    }
  }

  private static void assertCborEncodeAndDecode(String expectedHex, Object value) {
    assertCborEncode(expectedHex, value);
    assertCborDecode(value, expectedHex);
  }
}

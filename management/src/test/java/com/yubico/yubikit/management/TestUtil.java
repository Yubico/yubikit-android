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

package com.yubico.yubikit.management;

import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static org.junit.Assert.assertEquals;

import com.yubico.yubikit.core.Version;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

class TestUtil {

  static final Version defaultVersion = new Version(2, 2, 2);

  static Map<Integer, byte[]> tlvs(Integer tag, @Nullable byte[] data) {
    Map<Integer, byte[]> tlvs = new HashMap<>();
    tlvs.put(tag, data);
    return tlvs;
  }

  static Map<Integer, byte[]> emptyTlvs() {
    return new HashMap<>();
  }

  static void assertShortEquals(int expected, @Nullable Short value) {
    assertEquals(Short.valueOf((short) expected), value);
  }

  static void assertByteEquals(int expected, @Nullable Byte value) {
    assertEquals(Byte.valueOf((byte) expected), value);
  }

  static void assertIntegerEquals(int expected, @Nullable Integer value) {
    assertEquals(Integer.valueOf(expected), value);
  }

  static void assertIsFalse(@Nullable Boolean value) {
    assertEquals(FALSE, value);
  }

  static void assertIsTrue(@Nullable Boolean value) {
    assertEquals(TRUE, value);
  }
}

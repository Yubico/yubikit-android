/*
 * Copyright (C) 2023-2026 Yubico.
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

package com.yubico.yubikit.fido.webauthn;

import com.yubico.yubikit.core.internal.codec.Base64;
import java.math.BigDecimal;
import org.jspecify.annotations.Nullable;

class SerializationUtils {
  static Object serializeBytes(byte[] value, SerializationType serializationType) {
    switch (serializationType) {
      case JSON:
        {
          return Base64.toUrlSafeString(value);
        }

      case CBOR:
        {
          return value;
        }
    }

    throw new IllegalArgumentException("Invalid serialization type");
  }

  static byte[] deserializeBytes(Object value, SerializationType serializationType) {
    switch (serializationType) {
      case JSON:
        {
          return Base64.fromUrlSafeString((String) value);
        }

      case CBOR:
        {
          return (byte[]) value;
        }
    }

    throw new IllegalArgumentException("Invalid serialization type");
  }

  /**
   * Reads a 32-bit signed integer (WebIDL {@code long}, the type of {@code
   * COSEAlgorithmIdentifier}). Note that WebIDL {@code long} is 32 bits wide, like a Java {@code
   * int}, not like a Java {@code long}.
   *
   * <p>A JSON number has no integer type, and some clients send an integral value as a float (-7.0
   * for -7). WebIDL converts any number to an integer by truncating toward zero, wrapping modulo
   * 2^32, and rejecting NaN and infinity, which is what this does.
   *
   * @throws IllegalArgumentException if the value is not a finite number
   */
  static int deserializeInt(@Nullable Object value) {
    if (!(value instanceof Number)) {
      throw new IllegalArgumentException("Expected a number, got " + value);
    }
    if (value instanceof Float || value instanceof Double) {
      double d = ((Number) value).doubleValue();
      if (Double.isNaN(d) || Double.isInfinite(d)) {
        throw new IllegalArgumentException("Expected a finite number, got " + d);
      }
      // Exact conversion, truncating toward zero. BigInteger.intValue() keeps the low 32 bits,
      // which wraps modulo 2^32 as WebIDL requires; a (int) cast would saturate instead.
      return new BigDecimal(d).toBigInteger().intValue();
    }
    return ((Number) value).intValue();
  }
}

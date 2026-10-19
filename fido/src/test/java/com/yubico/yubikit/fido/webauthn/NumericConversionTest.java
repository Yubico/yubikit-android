/*
 * Copyright (C) 2026 Yubico.
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

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class NumericConversionTest {
  private static PublicKeyCredentialParameters parse(Object alg) {
    Map<String, Object> map = new HashMap<>();
    map.put("type", "public-key");
    map.put("alg", alg);
    return PublicKeyCredentialParameters.fromMap(map, SerializationType.JSON);
  }

  @Test
  public void algAcceptsIntegralTypes() {
    assertEquals(-7, parse(-7).getAlg());
    assertEquals(-7, parse(-7L).getAlg());
  }

  @Test
  public void algAcceptsFloatingPointFromJson() {
    assertEquals(-7, parse(-7.0).getAlg());
    assertEquals(-257, parse(-257.0f).getAlg());
  }

  @Test
  public void algTruncatesTowardZero() {
    assertEquals(-7, parse(-7.9).getAlg());
    assertEquals(7, parse(7.9).getAlg());
  }

  @Test
  public void deserializeIntWrapsModulo2To32() {
    assertEquals(-1, SerializationUtils.deserializeInt(4294967295.0));
    assertEquals(0, SerializationUtils.deserializeInt(4294967296L));
  }

  @Test(expected = IllegalArgumentException.class)
  public void algRejectsNaN() {
    parse(Double.NaN);
  }

  @Test(expected = IllegalArgumentException.class)
  public void algRejectsInfinity() {
    parse(Double.POSITIVE_INFINITY);
  }

  @Test(expected = IllegalArgumentException.class)
  public void algRejectsString() {
    parse("-7");
  }

  @Test(expected = IllegalArgumentException.class)
  public void algRejectsMissing() {
    parse(null);
  }
}

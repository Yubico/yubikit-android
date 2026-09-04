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

package com.yubico.yubikit.fido;

import com.yubico.yubikit.core.internal.codec.Base64;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import org.junit.Assert;
import org.junit.Test;

public class CoseTest {

  private static final Map<Integer, Object> EMPTY_COSE = new HashMap<>();

  private static String encode(byte[] data) {
    return Base64.toUrlSafeString(data);
  }

  private static void assertDecodesTo(Map<Integer, Object> coseKey, String expectedSpki)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    PublicKey publicKey = Cose.getPublicKey(coseKey);
    Assert.assertNotNull(publicKey);
    Assert.assertEquals(expectedSpki, encode(publicKey.getEncoded()));
  }

  @Test(expected = NullPointerException.class)
  public void getAlgorithmOnInvalidData() {
    Assert.assertNull(Cose.getAlgorithm(EMPTY_COSE));
  }

  @Test
  public void getAlgorithm() {
    Assert.assertEquals(Integer.valueOf(-257), Cose.getAlgorithm(CoseTestVectors.rs256()));
    Assert.assertEquals(Integer.valueOf(-7), Cose.getAlgorithm(CoseTestVectors.es256()));
    Assert.assertEquals(Integer.valueOf(-35), Cose.getAlgorithm(CoseTestVectors.es384()));
    Assert.assertEquals(Integer.valueOf(-36), Cose.getAlgorithm(CoseTestVectors.es512()));
    Assert.assertEquals(Integer.valueOf(-8), Cose.getAlgorithm(CoseTestVectors.eddsa()));
  }

  @Test
  public void getPublicKeyRS256() throws InvalidKeySpecException, NoSuchAlgorithmException {
    assertDecodesTo(CoseTestVectors.rs256(), CoseTestVectors.RS256_SPKI);
  }

  @Test
  public void getPublicKeyES256() throws InvalidKeySpecException, NoSuchAlgorithmException {
    assertDecodesTo(CoseTestVectors.es256(), CoseTestVectors.ES256_SPKI);
  }

  @Test
  public void getPublicKeyES384() throws InvalidKeySpecException, NoSuchAlgorithmException {
    assertDecodesTo(CoseTestVectors.es384(), CoseTestVectors.ES384_SPKI);
  }

  @Test
  public void getPublicKeyES512() throws InvalidKeySpecException, NoSuchAlgorithmException {
    assertDecodesTo(CoseTestVectors.es512(), CoseTestVectors.ES512_SPKI);
  }

  @Test
  public void getPublicKeyEDDSA() throws InvalidKeySpecException, NoSuchAlgorithmException {
    assertDecodesTo(CoseTestVectors.eddsa(), CoseTestVectors.EDDSA_SPKI);
  }

  /*
   * Regression coverage for signed decoding of EC2 coordinates. The vectors and the round-trip
   * assertion live in CoseTestVectors so that this test and the Android instrumented test in
   * :testing-android share one source of truth; see that class for why these coordinates matter.
   *
   * The plain high-bit case (negative, but no truncation) is already covered by getPublicKeyES256,
   * whose x starts 0xC1.
   */

  @Test
  public void getPublicKeyES256TruncatingX()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    CoseTestVectors.assertRoundTrip(CoseTestVectors.ES256_TRUNCATING_X);
  }

  @Test
  public void getPublicKeyES256TruncatingY()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    CoseTestVectors.assertRoundTrip(CoseTestVectors.ES256_TRUNCATING_Y);
  }

  @Test
  public void getPublicKeyES384TruncatingX()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    CoseTestVectors.assertRoundTrip(CoseTestVectors.ES384_TRUNCATING_X);
  }

  @Test
  public void getPublicKeyES256LeadingFf()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    CoseTestVectors.assertRoundTrip(CoseTestVectors.ES256_LEADING_FF);
  }
}

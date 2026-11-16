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

import static com.yubico.yubikit.fido.TestUtils.decodeHex;

import com.yubico.yubikit.core.internal.codec.Base64;
import java.io.ByteArrayOutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

  // Regression coverage for signed EC2 coordinate decoding (shared in CoseTestVectors).
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

  // DER SubjectPublicKeyInfo prefix for each ML-DSA parameter set (RFC 9881): SEQUENCE,
  // AlgorithmIdentifier with OID 2.16.840.1.101.3.4.3.{17,18,19} and no parameters, then the
  // BIT STRING header with zero unused bits. The raw public key follows.
  private static final String MLDSA_44_SPKI_PREFIX =
      "30820532" + "300b" + "0609608648016503040311" + "0382052100";
  private static final String MLDSA_65_SPKI_PREFIX =
      "308207b2" + "300b" + "0609608648016503040312" + "038207a100";
  private static final String MLDSA_87_SPKI_PREFIX =
      "30820a32" + "300b" + "0609608648016503040313" + "03820a2100";

  private static byte[] rawKey(int length) {
    byte[] key = new byte[length];
    for (int i = 0; i < length; i++) {
      key[i] = (byte) (i * 7 + 3);
    }
    return key;
  }

  private static Map<Integer, Object> akpKey(int alg, byte[] pub) {
    Map<Integer, Object> cose = new HashMap<>();
    cose.put(1, 7); // kty: AKP
    cose.put(3, alg);
    cose.put(-1, pub);
    return cose;
  }

  private static void assertMlDsa(int alg, int keyLength, String spkiPrefix)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    byte[] pub = rawKey(keyLength);
    ByteArrayOutputStream expected = new ByteArrayOutputStream();
    byte[] prefix = decodeHex(spkiPrefix);
    expected.write(prefix, 0, prefix.length);
    expected.write(pub, 0, pub.length);

    // An app may register a provider for ML-DSA, as here with Bouncy Castle
    Security.addProvider(new BouncyCastleProvider());
    try {
      PublicKey publicKey = Cose.getPublicKey(akpKey(alg, pub));
      Assert.assertNotNull(publicKey);
      Assert.assertArrayEquals(expected.toByteArray(), publicKey.getEncoded());
    } finally {
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }
  }

  @Test
  public void getPublicKeyMlDsa44() throws InvalidKeySpecException, NoSuchAlgorithmException {
    assertMlDsa(-48, 1312, MLDSA_44_SPKI_PREFIX);
  }

  @Test
  public void getPublicKeyMlDsa65() throws InvalidKeySpecException, NoSuchAlgorithmException {
    assertMlDsa(-49, 1952, MLDSA_65_SPKI_PREFIX);
  }

  @Test
  public void getPublicKeyMlDsa87() throws InvalidKeySpecException, NoSuchAlgorithmException {
    assertMlDsa(-50, 2592, MLDSA_87_SPKI_PREFIX);
  }

  @Test(expected = IllegalArgumentException.class)
  public void getPublicKeyAkpUnknownAlgorithm()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    Cose.getPublicKey(akpKey(-51, rawKey(1312)));
  }

  @Test(expected = IllegalArgumentException.class)
  public void getPublicKeyMlDsaWrongKeyLength()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    Cose.getPublicKey(akpKey(-48, rawKey(1952)));
  }

  @Test(expected = IllegalArgumentException.class)
  public void getPublicKeyUnknownKeyType()
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    Map<Integer, Object> cose = akpKey(-48, rawKey(1312));
    cose.put(1, 99);
    Cose.getPublicKey(cose);
  }
}

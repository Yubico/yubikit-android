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

import static com.yubico.yubikit.fido.TestUtils.decodeHex;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.CoseTestVectors;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Test;

public class AuthenticatorAttestationResponseTest {

  private static final byte FLAG_UP_AT = 0x41;

  private static AuthenticatorAttestationResponse responseFor(Map<Integer, ?> cosePublicKey) {
    AttestedCredentialData credentialData =
        new AttestedCredentialData(new byte[16], new byte[] {1, 2, 3, 4}, cosePublicKey);
    AuthenticatorData authenticatorData =
        new AuthenticatorData(new byte[32], FLAG_UP_AT, 0, credentialData, null, new byte[0]);
    AttestationObject attestationObject =
        new AttestationObject("none", authenticatorData, Collections.emptyMap(), null, null, null);
    return new AuthenticatorAttestationResponse(
        new byte[0], Collections.emptyList(), attestationObject);
  }

  private static Map<Integer, Object> mlDsa44Key(byte[] pub) {
    Map<Integer, Object> cose = new HashMap<>();
    cose.put(1, 7); // kty: AKP
    cose.put(3, -48); // alg: ML-DSA-44
    cose.put(-1, pub);
    return cose;
  }

  @Test
  public void mlDsa44PublicKeyWithProvider() {
    byte[] pub = new byte[1312];
    Arrays.fill(pub, (byte) 0x5a);
    byte[] prefix = decodeHex("30820532300b06096086480165030403110382052100");
    byte[] expected = Arrays.copyOf(prefix, prefix.length + pub.length);
    System.arraycopy(pub, 0, expected, prefix.length, pub.length);

    Security.addProvider(new BouncyCastleProvider());
    try {
      AuthenticatorAttestationResponse response = responseFor(mlDsa44Key(pub));
      assertArrayEquals(expected, response.getPublicKey());
      assertEquals(Integer.valueOf(-48), response.getPublicKeyAlgorithm());
    } finally {
      Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }
  }

  /** WebAuthn allows a null public key when the client does not support the algorithm. */
  @Test
  public void mlDsa44PublicKeyWithoutProviderIsNull() {
    // Remove the providers that support ML-DSA (some JDKs have one), and restore them after
    List<Provider> installed = Arrays.asList(Security.getProviders());
    Provider[] mlDsaProviders = Security.getProviders("KeyFactory.ML-DSA");
    List<Provider> removed =
        mlDsaProviders == null ? Collections.emptyList() : Arrays.asList(mlDsaProviders);
    for (Provider provider : removed) {
      Security.removeProvider(provider.getName());
    }
    try {
      AuthenticatorAttestationResponse response = responseFor(mlDsa44Key(new byte[1312]));
      assertNull(response.getPublicKey());
      assertEquals(Integer.valueOf(-48), response.getPublicKeyAlgorithm());
    } finally {
      for (Provider provider : removed) {
        Security.insertProviderAt(provider, installed.indexOf(provider) + 1);
      }
    }
  }

  @Test
  public void unknownKeyTypeYieldsNullPublicKey() {
    Map<Integer, Object> cose = new HashMap<>();
    cose.put(1, 99);
    cose.put(3, -1000);
    cose.put(-1, new byte[32]);

    AuthenticatorAttestationResponse response = responseFor(cose);

    assertNull(response.getPublicKey());
    assertEquals(Integer.valueOf(-1000), response.getPublicKeyAlgorithm());
  }

  @Test
  public void es256PublicKeyUnchanged() {
    AuthenticatorAttestationResponse response = responseFor(CoseTestVectors.es256());
    assertArrayEquals(
        Base64.fromUrlSafeString(CoseTestVectors.ES256_SPKI), response.getPublicKey());
  }
}

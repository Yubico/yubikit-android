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

package com.yubico.yubikit.fido.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorData;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;

public class UtilsTest {

  private static PublicKeyCredentialCreationOptions options(
      List<PublicKeyCredentialParameters> params) {
    return options(new byte[] {1}, params);
  }

  private static PublicKeyCredentialCreationOptions options(
      byte[] userId, List<PublicKeyCredentialParameters> params) {
    return new PublicKeyCredentialCreationOptions(
        new PublicKeyCredentialRpEntity("Example", "example.com"),
        new PublicKeyCredentialUserEntity("user", userId, "A User"),
        new byte[32],
        params,
        null,
        null,
        null,
        null,
        null);
  }

  @Test
  public void emptyPubKeyCredParamsDefaultToEs256ThenRs256() {
    List<PublicKeyCredentialParameters> params =
        Utils.getPubKeyCredParams(options(Collections.emptyList()));

    assertEquals(2, params.size());
    assertEquals(PublicKeyCredentialType.PUBLIC_KEY, params.get(0).getType());
    assertEquals(-7, params.get(0).getAlg());
    assertEquals(PublicKeyCredentialType.PUBLIC_KEY, params.get(1).getType());
    assertEquals(-257, params.get(1).getAlg());
  }

  @Test
  public void nonEmptyPubKeyCredParamsArePassedThrough() {
    List<PublicKeyCredentialParameters> requested =
        Collections.singletonList(
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -8));

    assertSame(requested, Utils.getPubKeyCredParams(options(requested)));
  }

  @Test
  public void userIdMustBe1To64Bytes() throws ClientError {
    Utils.checkUserId(options(new byte[1], Collections.emptyList()));
    Utils.checkUserId(options(new byte[64], Collections.emptyList()));
    assertThrows(
        ClientError.class, () -> Utils.checkUserId(options(new byte[0], Collections.emptyList())));
    assertThrows(
        ClientError.class, () -> Utils.checkUserId(options(new byte[65], Collections.emptyList())));
  }

  /** A credential whose COSE public key is given, in an attestation object. */
  private static AttestationObject attestationWithKey(Map<Integer, Object> cosePublicKey)
      throws Exception {
    ByteArrayOutputStream authData = new ByteArrayOutputStream();
    authData.write(new byte[32]); // rpIdHash
    authData.write(0x41); // UP, AT
    authData.write(new byte[4]); // signCount
    authData.write(new byte[16]); // aaguid
    authData.write(new byte[] {0, 1, 7}); // credential id length 1, id
    authData.write(Cbor.encode(cosePublicKey));
    return new AttestationObject(
        "none",
        AuthenticatorData.parseFrom(ByteBuffer.wrap(authData.toByteArray())),
        Collections.emptyMap(),
        null,
        null,
        null);
  }

  @Test
  public void attestationResponseRejectsMalformedCredentialKey() throws Exception {
    Map<Integer, Object> algAsText = new HashMap<>();
    algAsText.put(1, 2);
    algAsText.put(3, "ES256");
    Map<Integer, Object> missingCoordinates = new HashMap<>();
    missingCoordinates.put(1, 2);
    missingCoordinates.put(3, -7);
    missingCoordinates.put(-1, 1);
    Map<Integer, Object> keyTypeAsBytes = new HashMap<>();
    keyTypeAsBytes.put(1, new byte[] {2});
    keyTypeAsBytes.put(3, -7);
    for (Map<Integer, Object> cose : Arrays.asList(algAsText, missingCoordinates, keyTypeAsBytes)) {
      AttestationObject attestation = attestationWithKey(cose);
      assertThrows(
          cose.toString(),
          BadResponseException.class,
          () ->
              Utils.attestationResponse(
                  new byte[] {'{', '}'}, Collections.emptyList(), attestation));
    }
  }

  @Test
  public void attestationResponseAcceptsUnsupportedKeyType() throws Exception {
    // Well formed but unknown to the SDK: the response has no public key, as WebAuthn allows
    Map<Integer, Object> cose = new HashMap<>();
    cose.put(1, 99);
    cose.put(3, -1000);
    AuthenticatorAttestationResponse response =
        Utils.attestationResponse(
            new byte[] {'{', '}'}, Collections.emptyList(), attestationWithKey(cose));
    assertNull(response.getPublicKey());
    assertEquals(Integer.valueOf(-1000), response.getPublicKeyAlgorithm());
  }
}

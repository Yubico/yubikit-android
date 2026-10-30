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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.FidoTestState;
import com.yubico.yubikit.fido.ctap.Ctap1Session;
import com.yubico.yubikit.fido.utils.TestData;
import com.yubico.yubikit.fido.webauthn.AttestationConveyancePreference;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Checks the attestation format returned for each attestation conveyance preference: unless direct,
 * indirect or enterprise is requested, the attestation statement must be replaced by the "none"
 * format, and the credential must stay usable.
 */
public class AttestationConveyanceTests {

  private static final String[] SUPPRESSING = {null, AttestationConveyancePreference.NONE};
  private static final String[] CONVEYING = {
    AttestationConveyancePreference.DIRECT, AttestationConveyancePreference.INDIRECT
  };

  public static void testCtap2(FidoTestState state) throws Throwable {
    for (String preference : SUPPRESSING) {
      verifyCtap2(state, preference, true);
    }
    for (String preference : CONVEYING) {
      verifyCtap2(state, preference, false);
    }
  }

  public static void testCtap1(FidoTestState state) throws Throwable {
    for (String preference : SUPPRESSING) {
      verifyCtap1(state, preference, true);
    }
    for (String preference : CONVEYING) {
      verifyCtap1(state, preference, false);
    }
  }

  private static void verifyCtap2(
      FidoTestState state, @Nullable String preference, boolean suppressed) throws Throwable {
    state.withCtap2(
        session -> {
          PublicKeyCredential credential =
              new Ctap2Client(session)
                  .makeCredential(
                      TestData.CLIENT_DATA_JSON_CREATE_PROVIDER,
                      options(preference),
                      TestData.RP_ID,
                      TestData.PIN,
                      null,
                      null);
          verify(credential, suppressed);
        });
  }

  private static void verifyCtap1(
      FidoTestState state, @Nullable String preference, boolean suppressed) throws Throwable {
    state.withCtap1(
        session -> {
          verify(makeCtap1Credential(session, preference), suppressed);
        });
  }

  private static PublicKeyCredential makeCtap1Credential(
      Ctap1Session session, @Nullable String preference) throws Exception {
    return new Ctap1Client(session)
        .makeCredential(
            TestData.CLIENT_DATA_JSON_CREATE_PROVIDER,
            options(preference),
            TestData.RP_ID,
            null,
            null,
            null);
  }

  private static PublicKeyCredentialCreationOptions options(@Nullable String attestation) {
    return new PublicKeyCredentialCreationOptions(
        TestData.RP,
        TestData.USER,
        TestData.CHALLENGE,
        Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
        (long) 90000,
        null,
        new AuthenticatorSelectionCriteria(null, ResidentKeyRequirement.DISCOURAGED, null),
        attestation,
        null);
  }

  @SuppressWarnings("unchecked")
  private static void verify(PublicKeyCredential credential, boolean suppressed) {
    AuthenticatorAttestationResponse response =
        (AuthenticatorAttestationResponse) credential.getResponse();
    Map<String, ?> attestationObject =
        (Map<String, ?>) Cbor.decode(response.getAttestationObject());
    Map<String, ?> statement = (Map<String, ?>) attestationObject.get("attStmt");
    if (suppressed) {
      assertEquals("none", attestationObject.get("fmt"));
      assertTrue("Attestation statement should be empty", statement.isEmpty());
    } else {
      assertNotEquals("none", attestationObject.get("fmt"));
      assertTrue("Attestation certificate missing", statement.containsKey("x5c"));
    }

    // the credential must be usable whatever attestation is returned
    assertNotNull("Credential public key missing", response.getPublicKey());
    assertArrayEquals(
        credential.getRawId(),
        Objects.requireNonNull(response.getAuthenticatorData().getAttestedCredentialData())
            .getCredentialId());
  }
}

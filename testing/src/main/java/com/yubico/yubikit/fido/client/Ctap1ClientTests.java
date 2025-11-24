/*
 * Copyright (C) 2020-2025 Yubico.
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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import com.yubico.yubikit.fido.FidoTestState;
import com.yubico.yubikit.fido.utils.TestData;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAssertionResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

public class Ctap1ClientTests {

  public static void testMakeCredentialGetAssertion(FidoTestState state) throws Throwable {
    PublicKeyCredential cred =
        state.withCtap1(
            session -> {
              Ctap1Client ctap1Client = new Ctap1Client(session);

              PublicKeyCredentialCreationOptions creationOptionsNonRk =
                  getCreateOptions(
                      new PublicKeyCredentialUserEntity(
                          "user", "user".getBytes(StandardCharsets.UTF_8), "User"),
                      Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                      null);
              PublicKeyCredential pk =
                  ctap1Client.makeCredential(
                      TestData.CLIENT_DATA_JSON_CREATE_PROVIDER,
                      creationOptionsNonRk,
                      Objects.requireNonNull(creationOptionsNonRk.getRp().getId()),
                      null,
                      null,
                      null);
              AuthenticatorAttestationResponse responseNonRk =
                  (AuthenticatorAttestationResponse) pk.getResponse();
              assertNotNull("Failed to make non resident key credential", responseNonRk);
              assertNotNull(
                  "Credential missing attestation object", responseNonRk.getAttestationObject());
              assertNotNull(
                  "Credential missing client data JSON", responseNonRk.getClientDataJson());
              return pk;
            });

    // Get assertions
    state.withCtap1(
        session -> {
          Ctap1Client ctap1Client = new Ctap1Client(session);
          PublicKeyCredentialRequestOptions requestOptions =
              new PublicKeyCredentialRequestOptions(
                  TestData.CHALLENGE,
                  (long) 90000,
                  TestData.RP_ID,
                  Collections.singletonList(
                      new PublicKeyCredentialDescriptor(
                          PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, cred.getRawId())),
                  null,
                  null);

          PublicKeyCredential credential =
              ctap1Client.getAssertion(
                  TestData.CLIENT_DATA_JSON_GET_PROVIDER,
                  requestOptions,
                  TestData.RP_ID,
                  null,
                  null);
          AuthenticatorAssertionResponse response =
              (AuthenticatorAssertionResponse) credential.getResponse();
          assertNotNull(
              "Assertion response missing authenticator data", response.getAuthenticatorData());
          assertNotNull("Assertion response missing signature", response.getSignature());
          assertNull("Assertion response missing user handle", response.getUserHandle());
        });
  }

  private static PublicKeyCredentialCreationOptions getCreateOptions(
      @Nullable PublicKeyCredentialUserEntity user,
      List<PublicKeyCredentialParameters> credParams,
      @Nullable List<PublicKeyCredentialDescriptor> excludeCredentials) {
    return getCreateOptions(user, credParams, excludeCredentials, null);
  }

  private static PublicKeyCredentialCreationOptions getCreateOptions(
      @Nullable PublicKeyCredentialUserEntity user,
      List<PublicKeyCredentialParameters> credParams,
      @Nullable List<PublicKeyCredentialDescriptor> excludeCredentials,
      @Nullable String userVerification) {
    if (user == null) {
      user = TestData.USER;
    }
    PublicKeyCredentialRpEntity rp = TestData.RP;
    AuthenticatorSelectionCriteria criteria =
        new AuthenticatorSelectionCriteria(
            null, ResidentKeyRequirement.DISCOURAGED, userVerification);
    return new PublicKeyCredentialCreationOptions(
        rp,
        user,
        TestData.CHALLENGE,
        credParams,
        (long) 90000,
        excludeCredentials,
        criteria,
        null,
        null);
  }
}

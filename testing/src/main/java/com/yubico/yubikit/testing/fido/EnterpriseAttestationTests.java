/*
 * Copyright (C) 2020-2024 Yubico.
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

package com.yubico.yubikit.testing.fido;

import static java.lang.Boolean.FALSE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.client.BasicWebAuthnClient;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Config;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AttestationConveyancePreference;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import java.io.IOException;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

public class EnterpriseAttestationTests {

  static void enableEp(Ctap2Session session, FidoTestState state)
      throws CommandException, IOException {
    // enable ep if not enabled
    if (FALSE.equals(session.getCachedInfo().getOptions().get("ep"))) {

      ClientPin clientPin = new ClientPin(session, state.getPinUvAuthProtocol());
      byte[] pinToken = clientPin.getPinToken(TestData.PIN, ClientPin.PIN_PERMISSION_ACFG, null);
      final Config config = new Config(session, state.getPinUvAuthProtocol(), pinToken);
      config.enableEnterpriseAttestation();
    }
  }

  // test with RP ID in platform RP ID list
  public static void testSupportedPlatformManagedEA(Ctap2Session session, FidoTestState state)
      throws Throwable {
    assumeTrue(
        "Enterprise attestation not supported",
        session.getCachedInfo().getOptions().containsKey("ep"));
    enableEp(session, state);
    BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
    webauthn
        .getUserAgentConfiguration()
        .setEpSupportedRpIds(Collections.singletonList(TestData.RP_ID));

    PublicKeyCredential credential =
        makeCredential(webauthn, AttestationConveyancePreference.ENTERPRISE, 2);

    final Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
    assertNotNull(attestationObject);
    assertTrue((Boolean) attestationObject.get("epAtt"));
  }

  // test with RP ID which is not in platform RP ID list
  public static void testUnsupportedPlatformManagedEA(Ctap2Session session, FidoTestState state)
      throws Throwable {
    assumeTrue(
        "Enterprise attestation not supported",
        session.getCachedInfo().getOptions().containsKey("ep"));

    enableEp(session, state);
    BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

    PublicKeyCredential credential =
        makeCredential(webauthn, AttestationConveyancePreference.ENTERPRISE, 2);

    Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
    assertNotNull(attestationObject);
    assertTrue(
        !attestationObject.containsKey("epAtt") || FALSE.equals(attestationObject.get("epAtt")));
  }

  public static void testVendorFacilitatedEA(Ctap2Session session, FidoTestState state)
      throws Throwable {
    assumeTrue(
        "Enterprise attestation not supported",
        session.getCachedInfo().getOptions().containsKey("ep"));

    enableEp(session, state);
    BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
    webauthn
        .getUserAgentConfiguration()
        .setEpSupportedRpIds(Collections.singletonList(TestData.RP_ID));

    PublicKeyCredential credential =
        makeCredential(webauthn, AttestationConveyancePreference.ENTERPRISE, 1);

    final Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
    assertNotNull(attestationObject);
    assertEquals(Boolean.TRUE, attestationObject.get("epAtt"));
  }

  // test with different PublicKeyCredentialCreationOptions AttestationConveyancePreference
  // values
  public static void testCreateOptionsAttestationPreference(FidoTestState state) throws Throwable {

    state.withCtap2(
        session -> {
          assumeTrue(
              "Enterprise attestation not supported",
              session.getCachedInfo().getOptions().containsKey("ep"));
          enableEp(session, state);
        });

    // attestation = null
    state.withCtap2(
        session -> {
          final BasicWebAuthnClient webauthn = setupClient(session);
          PublicKeyCredential credential = makeCredential(webauthn, null, 2);

          Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
          assertNull(attestationObject.get("epAtt"));
        });

    // attestation = DIRECT
    state.withCtap2(
        session -> {
          final BasicWebAuthnClient webauthn = setupClient(session);
          PublicKeyCredential credential =
              makeCredential(webauthn, AttestationConveyancePreference.DIRECT, 2);
          Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
          assertNull(attestationObject.get("epAtt"));
        });

    // attestation = INDIRECT
    state.withCtap2(
        session -> {
          final BasicWebAuthnClient webauthn = setupClient(session);
          PublicKeyCredential credential =
              makeCredential(webauthn, AttestationConveyancePreference.DIRECT, 2);

          Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
          assertNull(attestationObject.get("epAtt"));
        });

    // attestation = ENTERPRISE but null enterpriseAttestation
    state.withCtap2(
        session -> {
          final BasicWebAuthnClient webauthn = setupClient(session);
          PublicKeyCredential credential =
              makeCredential(webauthn, AttestationConveyancePreference.ENTERPRISE, null);

          Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
          assertNull(attestationObject.get("epAtt"));
        });

    // attestation = ENTERPRISE
    state.withCtap2(
        session -> {
          final BasicWebAuthnClient webauthn = setupClient(session);
          PublicKeyCredential credential =
              makeCredential(webauthn, AttestationConveyancePreference.ENTERPRISE, 2);

          Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
          assertEquals(Boolean.TRUE, attestationObject.get("epAtt"));
        });
  }

  private static BasicWebAuthnClient setupClient(Ctap2Session session)
      throws IOException, CommandException {
    BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
    webauthn
        .getUserAgentConfiguration()
        .setEpSupportedRpIds(Collections.singletonList(TestData.RP_ID));
    return webauthn;
  }

  /** Helper method which creates test PublicKeyCredentialCreationOptions */
  private static PublicKeyCredentialCreationOptions getCredentialCreationOptions(
      @Nullable String attestation) {
    PublicKeyCredentialUserEntity user = TestData.USER;
    PublicKeyCredentialRpEntity rp = TestData.RP;
    AuthenticatorSelectionCriteria criteria =
        new AuthenticatorSelectionCriteria(null, ResidentKeyRequirement.REQUIRED, null);
    return new PublicKeyCredentialCreationOptions(
        rp,
        user,
        TestData.CHALLENGE,
        Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
        (long) 90000,
        null,
        criteria,
        attestation,
        null);
  }

  /** Helper method which extracts AuthenticatorAttestationResponse from the credential */
  @SuppressWarnings("unchecked")
  private static Map<String, ?> getAttestationObject(AuthenticatorResponse response) {
    AuthenticatorAttestationResponse authenticatorAttestationResponse =
        (AuthenticatorAttestationResponse) response;
    return (Map<String, ?>) Cbor.decode(authenticatorAttestationResponse.getAttestationObject());
  }

  /**
   * Helper method which creates a PublicKeyCredential with specific attestation and
   * enterpriseAttestation
   */
  private static PublicKeyCredential makeCredential(
      BasicWebAuthnClient webauthn,
      @Nullable String attestation,
      @Nullable Integer enterpriseAttestation)
      throws ClientError, IOException, CommandException {
    PublicKeyCredentialCreationOptions creationOptions = getCredentialCreationOptions(attestation);
    return webauthn.makeCredential(
        TestData.CLIENT_DATA_JSON_CREATE,
        creationOptions,
        Objects.requireNonNull(creationOptions.getRp().getId()),
        TestData.PIN,
        enterpriseAttestation,
        null);
  }
}

/*
 * Copyright (C) 2020-2023 Yubico.
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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static java.lang.Boolean.FALSE;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.client.BasicWebAuthnClient;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Config;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
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

@SuppressWarnings("unchecked")
public class EnterpriseAttestationTests {

    static void enableEp(Ctap2Session session, PinUvAuthProtocol pinUvAuthProtocol)
            throws CommandException, IOException {
        // enable ep if not enabled
        if (session.getCachedInfo().getOptions().get("ep") == FALSE) {

            ClientPin clientPin = new ClientPin(session, pinUvAuthProtocol);
            byte[] pinToken = clientPin.getPinToken(TestData.PIN, ClientPin.PIN_PERMISSION_ACFG, null);
            final Config config = new Config(session, pinUvAuthProtocol, pinToken);
            config.enableEnterpriseAttestation();

        }
    }

    // test with RP ID in platform RP ID list
    public static void testSupportedPlatformManagedEA(Ctap2Session session, Object... args) throws Throwable {
        PinUvAuthProtocol pinUvAuthProtocol = Ctap2ClientPinTests.getPinUvAuthProtocol(args);
        Ctap2ClientPinTests.ensureDefaultPinSet(session, pinUvAuthProtocol);
        enableEp(session, pinUvAuthProtocol);
        BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
        webauthn.getUserAgentConfiguration().setEpSupportedRpIds(Collections.singletonList(TestData.RP_ID));

        PublicKeyCredential credential = makeCredential(webauthn, AttestationConveyancePreference.ENTERPRISE, 2);

        final Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
        assertNotNull(attestationObject);
        assertTrue((Boolean) attestationObject.get("epAtt"));
    }

    // test with RP ID which is not in platform RP ID list
    public static void testUnsupportedPlatformManagedEA(Ctap2Session session, Object... args) throws Throwable {
        PinUvAuthProtocol pinUvAuthProtocol = Ctap2ClientPinTests.getPinUvAuthProtocol(args);
        Ctap2ClientPinTests.ensureDefaultPinSet(session, pinUvAuthProtocol);
        enableEp(session, pinUvAuthProtocol);
        BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

        PublicKeyCredential credential = makeCredential(webauthn, AttestationConveyancePreference.ENTERPRISE, 2);

        Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
        assertNotNull(attestationObject);
        assertTrue(!attestationObject.containsKey("epAtt") ||
                FALSE.equals(attestationObject.get("epAtt")));
    }

    public static void testVendorFacilitatedEA(Ctap2Session session, Object... args) throws Throwable {
        PinUvAuthProtocol pinUvAuthProtocol = Ctap2ClientPinTests.getPinUvAuthProtocol(args);
        Ctap2ClientPinTests.ensureDefaultPinSet(session, pinUvAuthProtocol);
        enableEp(session, pinUvAuthProtocol);
        BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
        webauthn.getUserAgentConfiguration().setEpSupportedRpIds(Collections.singletonList(TestData.RP_ID));

        PublicKeyCredential credential = makeCredential(webauthn, AttestationConveyancePreference.ENTERPRISE, 1);

        final Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
        assertNotNull(attestationObject);
        assertTrue((Boolean) attestationObject.get("epAtt"));
    }

    // test with different PublicKeyCredentialCreationOptions AttestationConveyancePreference
    // values
    public static void testCreateOptionsAttestationPreference(Ctap2Session session, Object... args) throws Throwable {
        PinUvAuthProtocol pinUvAuthProtocol = Ctap2ClientPinTests.getPinUvAuthProtocol(args);
        Ctap2ClientPinTests.ensureDefaultPinSet(session, pinUvAuthProtocol);
        enableEp(session, pinUvAuthProtocol);

        // setup
        BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
        webauthn.getUserAgentConfiguration().setEpSupportedRpIds(Collections.singletonList(
                TestData.RP_ID
        ));

        // attestation = null
        PublicKeyCredential credential = makeCredential(webauthn, null, 2);

        Map<String, ?> attestationObject = getAttestationObject(credential.getResponse());
        assertNull(attestationObject.get("epAtt"));

        // attestation = DIRECT
        credential = makeCredential(webauthn, AttestationConveyancePreference.DIRECT, 2);

        attestationObject = getAttestationObject(credential.getResponse());
        assertNull(attestationObject.get("epAtt"));

        // attestation = INDIRECT
        credential = makeCredential(webauthn, AttestationConveyancePreference.DIRECT, 2);

        attestationObject = getAttestationObject(credential.getResponse());
        assertNull(attestationObject.get("epAtt"));

        // attestation = ENTERPRISE but null enterpriseAttestation
        credential = makeCredential(webauthn, AttestationConveyancePreference.ENTERPRISE, null);

        attestationObject = getAttestationObject(credential.getResponse());
        assertNull(attestationObject.get("epAtt"));

        // attestation = ENTERPRISE
        credential = makeCredential(webauthn, AttestationConveyancePreference.ENTERPRISE, 2);

        attestationObject = getAttestationObject(credential.getResponse());
        assertTrue((Boolean) attestationObject.get("epAtt"));
    }

    /**
     * Helper method which creates test PublicKeyCredentialCreationOptions
     */
    private static PublicKeyCredentialCreationOptions getCredentialCreationOptions(
            @Nullable String attestation
    ) {
        PublicKeyCredentialUserEntity user = TestData.USER;
        PublicKeyCredentialRpEntity rp = TestData.RP;
        AuthenticatorSelectionCriteria criteria = new AuthenticatorSelectionCriteria(
                null,
                ResidentKeyRequirement.REQUIRED,
                null
        );
        return new PublicKeyCredentialCreationOptions(
                rp,
                user,
                TestData.CHALLENGE,
                Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                (long) 90000,
                null,
                criteria,
                attestation,
                null
        );
    }

    /**
     * Helper method which extracts AuthenticatorAttestationResponse from the credential
     */
    private static Map<String, ?> getAttestationObject(AuthenticatorResponse response) {
        AuthenticatorAttestationResponse authenticatorAttestationResponse =
                (AuthenticatorAttestationResponse) response;
        return (Map<String, ?>)
                Cbor.decode(authenticatorAttestationResponse.getAttestationObject());
    }

    /**
     * Helper method which creates a PublicKeyCredential with specific attestation and enterpriseAttestation
     */
    private static PublicKeyCredential makeCredential(
            BasicWebAuthnClient webauthn,
            @Nullable String attestation,
            @Nullable Integer enterpriseAttestation
    ) throws ClientError, IOException, CommandException {
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
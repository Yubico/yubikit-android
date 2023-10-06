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

import static org.hamcrest.CoreMatchers.instanceOf;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.client.BasicWebAuthnClient;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.client.CredentialManager;
import com.yubico.yubikit.fido.client.MultipleAssertionsAvailable;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.FidoVersion;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAssertionResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class BasicWebAuthnClientTests {

    public static void testMakeCredentialGetAssertion(Ctap2Session session) throws Throwable {

        Ctap2ClientPinTests.ensureDefaultPinSet(session);

        BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
        List<byte[]> deleteCredIds = new ArrayList<>();

        // Make a non rk credential
        PublicKeyCredentialCreationOptions creationOptionsNonRk = getCreateOptions(
                new PublicKeyCredentialUserEntity(
                        "rkuser",
                        "rkuser".getBytes(StandardCharsets.UTF_8),
                        "RkUser"
                ),
                false,
                Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                null
        );
        PublicKeyCredential credNonRk = webauthn.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE,
                creationOptionsNonRk,
                Objects.requireNonNull(creationOptionsNonRk.getRp().getId()),
                TestData.PIN,
                null,
                null
        );
        AuthenticatorAttestationResponse responseNonRk = (AuthenticatorAttestationResponse) credNonRk.getResponse();
        assertNotNull("Failed to make non resident key credential", responseNonRk);
        assertNotNull("Credential missing attestation object", responseNonRk.getAttestationObject());
        assertNotNull("Credential missing client data JSON", responseNonRk.getClientDataJson());

        // make a rk credential
        PublicKeyCredentialCreationOptions creationOptionsRk = getCreateOptions(
                new PublicKeyCredentialUserEntity(
                        "user",
                        "user".getBytes(StandardCharsets.UTF_8),
                        "User"
                ),
                true,
                Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                null);
        PublicKeyCredential credRk = webauthn.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE,
                creationOptionsRk,
                Objects.requireNonNull(creationOptionsRk.getRp().getId()),
                TestData.PIN,
                null,
                null
        );
        AuthenticatorAttestationResponse responseRk = (AuthenticatorAttestationResponse) credRk.getResponse();
        assertNotNull("Failed to make resident key credential", responseRk);
        assertNotNull("Credential missing attestation object", responseRk.getAttestationObject());
        assertNotNull("Credential missing client data JSON", responseRk.getClientDataJson());
        deleteCredIds.add((byte[]) parseCredentialData(getAuthenticatorDataFromAttestationResponse(responseRk)).get("credId"));

        // Get assertions
        PublicKeyCredentialRequestOptions requestOptions = new PublicKeyCredentialRequestOptions(
                TestData.CHALLENGE,
                (long) 90000,
                TestData.RP_ID,
                null,
                null,
                null
        );

        try {
            PublicKeyCredential credential = webauthn.getAssertion(
                    TestData.CLIENT_DATA_JSON_GET,
                    requestOptions,
                    TestData.RP_ID,
                    TestData.PIN,
                    null
            );
            AuthenticatorAssertionResponse response = (AuthenticatorAssertionResponse) credential.getResponse();
            assertNotNull("Assertion response missing authenticator data", response.getAuthenticatorData());
            assertNotNull("Assertion response missing signature", response.getSignature());
            assertNotNull("Assertion response missing user handle", response.getUserHandle());
        } catch (MultipleAssertionsAvailable multipleAssertionsAvailable) {
            fail("Got MultipleAssertionsAvailable even though there should only be one credential");
        }

        deleteCredentials(webauthn, deleteCredIds);
    }

    public static void testGetAssertionMultipleUsersRk(Ctap2Session session) throws Throwable {

        Ctap2ClientPinTests.ensureDefaultPinSet(session);

        BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
        List<byte[]> deleteCredIds = new ArrayList<>();

        Map<byte[], byte[]> userIdCredIdMap = new HashMap<>();

        // make 3 rk credential
        for (int i = 0; i < 3; i++) {
            PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(
                    "user" + i,
                    ("user" + i).getBytes(StandardCharsets.UTF_8),
                    "User" + i
            );
            PublicKeyCredentialCreationOptions creationOptions = getCreateOptions(
                    user,
                    true,
                    Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                    null
            );
            PublicKeyCredential credential = webauthn.makeCredential(
                    TestData.CLIENT_DATA_JSON_CREATE,
                    creationOptions,
                    Objects.requireNonNull(creationOptions.getRp().getId()),
                    TestData.PIN,
                    null,
                    null
            );
            AuthenticatorAttestationResponse response = (AuthenticatorAttestationResponse) credential.getResponse();
            byte[] credId = (byte[]) parseCredentialData(getAuthenticatorDataFromAttestationResponse(response)).get("credId");
            userIdCredIdMap.put(user.getId(), credId);
            deleteCredIds.add(credId);
        }

        // Get assertions
        PublicKeyCredentialRequestOptions requestOptions = new PublicKeyCredentialRequestOptions(
                TestData.CHALLENGE,
                (long) 90000,
                TestData.RP_ID,
                null,
                null,
                null
        );

        for (int i = 0; i < 3; i++) {
            try {
                webauthn.getAssertion(
                        TestData.CLIENT_DATA_JSON_GET,
                        requestOptions,
                        TestData.RP_ID,
                        TestData.PIN,
                        null
                );
                fail("Got single assertion even though multiple credentials exist");
            } catch (MultipleAssertionsAvailable multipleAssertionsAvailable) {
                List<PublicKeyCredentialUserEntity> users = multipleAssertionsAvailable.getUsers();
                assertNotNull("Assertion failed to return user list", users);
                assertTrue("There should be at least 3 users found", users.size() >= 3);
                PublicKeyCredentialUserEntity user = users.get(i);
                assertNotNull(user.getId());
                assertNotNull(user.getName());
                assertNotNull(user.getDisplayName());
                if (userIdCredIdMap.containsKey(user.getId())) {
                    PublicKeyCredential credential = multipleAssertionsAvailable.select(i);
                    AuthenticatorAssertionResponse assertion = (AuthenticatorAssertionResponse) credential.getResponse();
                    assertNotNull("Failed to get assertion", assertion);
                    assertNotNull("Assertion response missing authenticator data", assertion.getAuthenticatorData());
                    assertNotNull("Assertion response missing signature", assertion.getSignature());
                    assertNotNull("Assertion response missing user handle", assertion.getUserHandle());

                    assertArrayEquals(userIdCredIdMap.get(users.get(i).getId()), credential.getRawId());
                }
            }
        }

        deleteCredentials(webauthn, deleteCredIds);
    }

    public static void testGetAssertionWithAllowList(Ctap2Session session) throws Throwable {

        Ctap2ClientPinTests.ensureDefaultPinSet(session);

        BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);

        // Make 2 new credentials
        PublicKeyCredentialCreationOptions creationOptions1 = getCreateOptions(
                new PublicKeyCredentialUserEntity(
                        "user1",
                        "user1".getBytes(StandardCharsets.UTF_8),
                        "testUser1"
                ),
                false,
                Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                null
        );
        PublicKeyCredentialCreationOptions creationOptions2 = getCreateOptions(
                new PublicKeyCredentialUserEntity(
                        "user2",
                        "user2".getBytes(StandardCharsets.UTF_8),
                        "testUser2"
                ),
                false,
                Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                null
        );

        PublicKeyCredential cred1 = webauthn.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE,
                creationOptions1,
                Objects.requireNonNull(TestData.RP.getId()),
                TestData.PIN,
                null,
                null
        );

        byte[] credId1 = cred1.getRawId();

        PublicKeyCredential cred2 = webauthn.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE,
                creationOptions2,
                Objects.requireNonNull(TestData.RP.getId()),
                TestData.PIN,
                null,
                null
        );
        byte[] credId2 = cred2.getRawId();

        // GetAssertions with allowList containing only credId1
        List<PublicKeyCredentialDescriptor> allowCreds = Collections.singletonList(
                new PublicKeyCredentialDescriptor(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        credId1,
                        null
                )
        );
        PublicKeyCredentialRequestOptions requestOptions = new PublicKeyCredentialRequestOptions(
                TestData.CHALLENGE,
                (long) 90000,
                TestData.RP_ID,
                allowCreds,
                null,
                null
        );

        PublicKeyCredential credential = webauthn.getAssertion(
                TestData.CLIENT_DATA_JSON_GET,
                requestOptions,
                TestData.RP_ID,
                TestData.PIN,
                null
        );
        assertArrayEquals(credId1, credential.getRawId());

        // GetAssertions with allowList containing only credId2
        allowCreds = Collections.singletonList(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credId2, null));
        requestOptions = new PublicKeyCredentialRequestOptions(
                TestData.CHALLENGE, (long) 90000, TestData.RP_ID, allowCreds, null, null);

        credential = webauthn.getAssertion(
                TestData.CLIENT_DATA_JSON_GET,
                requestOptions,
                TestData.RP_ID,
                TestData.PIN,
                null
        );
        assertArrayEquals(credId2, credential.getRawId());
    }

    public static void testMakeCredentialWithExcludeList(Ctap2Session session) throws Throwable {

        Ctap2ClientPinTests.ensureDefaultPinSet(session);

        BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
        List<PublicKeyCredentialDescriptor> excludeList = new ArrayList<>();

        // Make a non RK credential
        PublicKeyCredentialCreationOptions creationOptions = getCreateOptions(
                null,
                false,
                Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                null
        );

        PublicKeyCredential credential = webauthn.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE,
                creationOptions,
                Objects.requireNonNull(creationOptions.getRp().getId()),
                TestData.PIN,
                null,
                null
        );
        excludeList.add(
                new PublicKeyCredentialDescriptor(
                        PublicKeyCredentialType.PUBLIC_KEY,
                        credential.getRawId(),
                        null
                )
        );

        // Make another non RK credential with exclude list including credId. Should fail
        creationOptions = getCreateOptions(
                null,
                false,
                Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                excludeList
        );
        try {
            webauthn.makeCredential(
                    TestData.CLIENT_DATA_JSON_CREATE,
                    creationOptions,
                    Objects.requireNonNull(creationOptions.getRp().getId()),
                    TestData.PIN,
                    null,
                    null
            );
            fail("Succeeded in making credential even though the credential was excluded");
        } catch (ClientError clientError) {
            assertEquals(ClientError.Code.DEVICE_INELIGIBLE, clientError.getErrorCode());
        }

        // Make another non RK credential with exclude list null. Should succeed
        creationOptions = getCreateOptions(
                null,
                false,
                Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                null
        );
        webauthn.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE,
                creationOptions,
                Objects.requireNonNull(creationOptions.getRp().getId()),
                TestData.PIN,
                null,
                null
        );
    }

    public static void testMakeCredentialKeyAlgorithms(Ctap2Session session) throws Throwable {
        Ctap2ClientPinTests.ensureDefaultPinSet(session);
        BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
        List<PublicKeyCredentialParameters> allCredParams = Arrays.asList(
                TestData.PUB_KEY_CRED_PARAMS_ES256,
                TestData.PUB_KEY_CRED_PARAMS_EDDSA);

        // Test individual algorithms
        for (PublicKeyCredentialParameters param : allCredParams) {
            PublicKeyCredentialCreationOptions creationOptions = getCreateOptions(
                    null, false, Collections.singletonList(param), null);
            PublicKeyCredential credential = webauthn.makeCredential(
                    TestData.CLIENT_DATA_JSON_CREATE,
                    creationOptions,
                    Objects.requireNonNull(creationOptions.getRp().getId()),
                    TestData.PIN,
                    null,
                    null
            );
            AuthenticatorAttestationResponse attestation = (AuthenticatorAttestationResponse) credential.getResponse();
            int alg = (Integer) Objects.requireNonNull(
                    parseCredentialData(
                            getAuthenticatorDataFromAttestationResponse(attestation)
                    ).get("keyAlgo")
            );
            assertEquals(param.getAlg(), alg);
        }

        // Test algorithm order: ES256 - EdDSA
        List<PublicKeyCredentialParameters> credParams = Arrays.asList(
                allCredParams.get(0),
                allCredParams.get(1));
        PublicKeyCredentialCreationOptions creationOptions = getCreateOptions(
                null,
                false,
                credParams,
                null
        );
        PublicKeyCredential credential = webauthn.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE,
                creationOptions,
                Objects.requireNonNull(creationOptions.getRp().getId()),
                TestData.PIN,
                null,
                null
        );
        AuthenticatorAttestationResponse attestation = (AuthenticatorAttestationResponse) credential.getResponse();
        int alg = (Integer) Objects.requireNonNull(
                parseCredentialData(
                        getAuthenticatorDataFromAttestationResponse(attestation)
                ).get("keyAlgo")
        );
        assertEquals(credParams.get(0).getAlg(), alg);

        // Test algorithm order: ALG_EdDSA - ALG_ES256
        credParams = Arrays.asList(
                allCredParams.get(1),
                allCredParams.get(0));
        creationOptions = getCreateOptions(null, false, credParams, null);
        credential = webauthn.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE,
                creationOptions,
                Objects.requireNonNull(creationOptions.getRp().getId()),
                TestData.PIN,
                null,
                null
        );
        attestation = (AuthenticatorAttestationResponse) credential.getResponse();
        alg = (Integer) Objects.requireNonNull(
                parseCredentialData(
                        getAuthenticatorDataFromAttestationResponse(attestation)
                ).get("keyAlgo")
        );
        assertEquals(credParams.get(0).getAlg(), alg);
    }

    public static void testClientPinManagement(Ctap2Session session) throws Throwable {
        Ctap2ClientPinTests.ensureDefaultPinSet(session);

        BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
        assertTrue(webauthn.isPinSupported());
        assertTrue(webauthn.isPinConfigured());

        char[] otherPin = "123123".toCharArray();

        webauthn.changePin(TestData.PIN, otherPin);

        try {
            webauthn.changePin(TestData.PIN, otherPin);
            fail("Wrong PIN was accepted");
        } catch (ClientError e) {
            assertThat(e.getErrorCode(), equalTo(ClientError.Code.BAD_REQUEST));
            assertThat(e.getCause(), instanceOf(CtapException.class));
            assertThat(((CtapException) Objects.requireNonNull(e.getCause())).getCtapError(),
                    is(CtapException.ERR_PIN_INVALID));
        }

        webauthn.changePin(otherPin, TestData.PIN);
    }


    public static void testClientCredentialManagement(Ctap2Session session) throws Throwable {
        Ctap2ClientPinTests.ensureDefaultPinSet(session);
        BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
        PublicKeyCredentialCreationOptions creationOptions = getCreateOptions(null, true,
                Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256),
                null);
        webauthn.makeCredential(
                TestData.CLIENT_DATA_JSON_CREATE,
                creationOptions,
                Objects.requireNonNull(creationOptions.getRp().getId()),
                TestData.PIN,
                null,
                null);

        CredentialManager credentialManager = webauthn.getCredentialManager(TestData.PIN);

        assertThat(credentialManager.getCredentialCount(), equalTo(1));

        List<String> rpIds = credentialManager.getRpIdList();
        assertThat(rpIds, equalTo(Collections.singletonList(TestData.RP_ID)));

        Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> credentials = credentialManager.getCredentials(TestData.RP_ID);
        assertThat(credentials.size(), equalTo(1));
        PublicKeyCredentialDescriptor key = credentials.keySet().iterator().next();
        assertThat(Objects.requireNonNull(credentials.get(key)).getId(), equalTo(TestData.USER_ID));

        credentialManager.deleteCredential(key);
        assertThat(credentialManager.getCredentialCount(), equalTo(0));
        assertTrue(credentialManager.getCredentials(TestData.RP_ID).isEmpty());
        assertTrue(credentialManager.getRpIdList().isEmpty());
    }

    private static PublicKeyCredentialCreationOptions getCreateOptions(
            @Nullable PublicKeyCredentialUserEntity user,
            boolean rk,
            List<PublicKeyCredentialParameters> credParams,
            @Nullable List<PublicKeyCredentialDescriptor> excludeCredentials
    ) {
        if (user == null) {
            user = TestData.USER;
        }
        PublicKeyCredentialRpEntity rp = TestData.RP;
        AuthenticatorSelectionCriteria criteria = new AuthenticatorSelectionCriteria(
                null,
                rk
                        ? ResidentKeyRequirement.REQUIRED
                        : ResidentKeyRequirement.DISCOURAGED,
                null
        );
        return new PublicKeyCredentialCreationOptions(
                rp,
                user,
                TestData.CHALLENGE,
                credParams,
                (long) 90000,
                excludeCredentials,
                criteria,
                null,
                null
        );
    }

    private static byte[] getAuthenticatorDataFromAttestationResponse(AuthenticatorAttestationResponse response) {
        byte[] attestObjBytes = response.getAttestationObject();
        @SuppressWarnings("unchecked")
        Map<String, Object> attestObj = (Map<String, Object>) Cbor.decode(attestObjBytes);
        return (byte[]) attestObj.get("authData");
    }

    private static Map<String, Object> parseCredentialData(final byte[] data) {
        ByteBuffer bb = ByteBuffer.wrap(data);
        byte[] rpIdHash = new byte[32];
        bb.get(rpIdHash);

        byte flags = bb.get();

        int signCount = bb.getInt();

        byte[] aaguid = new byte[16];
        bb.get(aaguid);

        short idLength = bb.getShort();
        byte[] credId = new byte[idLength];
        bb.get(credId);

        byte[] key = new byte[bb.remaining()];
        bb.get(key);

        Map<String, Object> credData = new HashMap<>();
        credData.put("rpIdHash", rpIdHash);
        credData.put("flags", flags);
        credData.put("signCount", signCount);
        credData.put("aaguid", aaguid);
        credData.put("credId", credId);
        credData.put("pubkey", key);
        credData.put("keyAlgo", getAlgoFromCredentialPublicKey(key));
        return credData;
    }

    private static int getAlgoFromCredentialPublicKey(byte[] pubKey) {
        @SuppressWarnings("unchecked")
        Map<Integer, ?> credPublicKey = (Map<Integer, ?>) Cbor.decode(pubKey);
        return (Integer) Objects.requireNonNull(credPublicKey.get(3));
    }

    private static void deleteCredentials(
            @Nonnull BasicWebAuthnClient webAuthnClient,
            @Nonnull List<byte[]> credIds
    ) throws IOException, CommandException, ClientError {
        CredentialManager credentialManager = webAuthnClient.getCredentialManager(TestData.PIN);
        for (byte[] credId : credIds) {
            credentialManager.deleteCredential(
                    new PublicKeyCredentialDescriptor(
                            PublicKeyCredentialType.PUBLIC_KEY,
                            credId,
                            null));
        }
    }
}
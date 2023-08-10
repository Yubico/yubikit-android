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

package com.yubico.yubikit.fido.webauthn;

import org.apache.commons.codec.binary.Base64;
import org.junit.Assert;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

/**
 * Test serialization and deserialization of WebAuthn data objects using toMap/fromMap as well as toBytes/fromBytes where applicable.
 * Also tests that each object can successfully serialize to and from CBOR.
 */
public class SerializationTest {
    private final SecureRandom random = new SecureRandom();

    private void compareRpEntities(PublicKeyCredentialRpEntity a, PublicKeyCredentialRpEntity b) {
        Assert.assertEquals(a.getId(), b.getId());
        Assert.assertEquals(a.getName(), b.getName());
    }

    @Test
    public void testRpEntity() {
        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity(
                "An Example Company", "example.com"
        );

        Map<String, ?> map = rp.toMap();

        Assert.assertEquals(rp.getId(), map.get("id"));
        Assert.assertEquals(rp.getName(), map.get("name"));

        compareRpEntities(rp, PublicKeyCredentialRpEntity.fromMap(map));
    }

    private void compareUserEntities(PublicKeyCredentialUserEntity a, PublicKeyCredentialUserEntity b) {
        Assert.assertArrayEquals(a.getId(), b.getId());
        Assert.assertEquals(a.getName(), b.getName());
        Assert.assertEquals(a.getDisplayName(), b.getDisplayName());
    }

    @Test
    public void testUserEntity() {
        byte[] userId = new byte[4 + random.nextInt(29)];
        random.nextBytes(userId);

        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(
                "user@example.com", userId,
                "A. User"
        );

        Map<String, ?> map = user.toMap();

        Assert.assertEquals(Base64.encodeBase64URLSafeString(user.getId()), (String) map.get("id"));
        Assert.assertEquals(user.getName(), map.get("name"));
        Assert.assertEquals(user.getDisplayName(), map.get("displayName"));

        compareUserEntities(user, PublicKeyCredentialUserEntity.fromMap(map));
    }

    private void compareParameters(PublicKeyCredentialParameters a, PublicKeyCredentialParameters b) {
        Assert.assertEquals(a.getType(), b.getType());
        Assert.assertEquals(a.getAlg(), b.getAlg());
    }

    private void compareParametersLists(List<PublicKeyCredentialParameters> a, List<PublicKeyCredentialParameters> b) {
        Assert.assertEquals(a.size(), b.size());
        for (int i = 0; i < a.size(); i++) {
            compareParameters(a.get(i), b.get(i));
        }
    }

    @Test
    public void testParameters() {
        PublicKeyCredentialParameters param = new PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                -7
        );

        Map<String, ?> map = param.toMap();

        Assert.assertEquals(param.getType(), map.get("type"));
        Assert.assertEquals(param.getAlg(), map.get("alg"));

        compareParameters(param, PublicKeyCredentialParameters.fromMap(map));
    }

    private void compareDescriptors(PublicKeyCredentialDescriptor a, PublicKeyCredentialDescriptor b) {
        Assert.assertEquals(a.getType(), b.getType());
        Assert.assertArrayEquals(a.getId(), b.getId());
        Assert.assertEquals(a.getTransports(), b.getTransports());
    }

    private void compareDescriptorLists(List<PublicKeyCredentialDescriptor> a, List<PublicKeyCredentialDescriptor> b) {
        Assert.assertEquals(a.size(), b.size());
        for (int i = 0; i < a.size(); i++) {
            compareDescriptors(a.get(i), b.get(i));
        }
    }

    @Test
    public void testDescriptor() {
        byte[] credentialId = new byte[4 + random.nextInt(29)];
        random.nextBytes(credentialId);

        PublicKeyCredentialDescriptor descriptor = new PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY,
                credentialId,
                Arrays.asList("USB", "NFC")
        );

        Map<String, ?> base64Map = descriptor.toMap();
        Assert.assertEquals(descriptor.getType(), base64Map.get("type"));
        Assert.assertArrayEquals(descriptor.getId(), Base64.decodeBase64((String) base64Map.get("id")));
        compareDescriptors(descriptor, PublicKeyCredentialDescriptor.fromMap(base64Map));

        Map<String, ?> map = descriptor.toMap();
        Assert.assertEquals(descriptor.getType(), map.get("type"));
        Assert.assertEquals(Base64.encodeBase64URLSafeString(descriptor.getId()), (String) map.get("id"));
        compareDescriptors(descriptor, PublicKeyCredentialDescriptor.fromMap(map));
    }

    private void compareSelectionCriteria(@Nullable AuthenticatorSelectionCriteria a, @Nullable AuthenticatorSelectionCriteria b) {
        if (a == null || b == null) {
            return;
        }
        Assert.assertEquals(a.getAuthenticatorAttachment(), b.getAuthenticatorAttachment());
        Assert.assertEquals(a.getResidentKey(), b.getResidentKey());
        Assert.assertEquals(a.getUserVerification(), b.getUserVerification());
    }

    @Test
    public void testSelectionCriteria() {
        AuthenticatorSelectionCriteria criteria = new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.PLATFORM,
                ResidentKeyRequirement.REQUIRED,
                UserVerificationRequirement.PREFERRED
        );

        Map<String, ?> map = criteria.toMap();

        Assert.assertNotNull(criteria.getAuthenticatorAttachment());
        Assert.assertNotNull(criteria.getResidentKey());
        Assert.assertEquals(criteria.getAuthenticatorAttachment(), map.get("authenticatorAttachment"));
        Assert.assertEquals(criteria.getUserVerification(), map.get("userVerification"));
        Assert.assertEquals(criteria.getResidentKey(), map.get("residentKey"));

        compareSelectionCriteria(criteria, AuthenticatorSelectionCriteria.fromMap(map));
    }

    private void compareCreationOptions(PublicKeyCredentialCreationOptions a, PublicKeyCredentialCreationOptions b) {
        compareRpEntities(a.getRp(), b.getRp());
        compareUserEntities(a.getUser(), b.getUser());
        Assert.assertArrayEquals(a.getChallenge(), b.getChallenge());
        compareParametersLists(a.getPubKeyCredParams(), b.getPubKeyCredParams());
        Assert.assertEquals(a.getTimeout(), b.getTimeout());
        compareDescriptorLists(a.getExcludeCredentials(), b.getExcludeCredentials());
        compareSelectionCriteria(a.getAuthenticatorSelection(), b.getAuthenticatorSelection());
        Assert.assertEquals(a.getAttestation(), b.getAttestation());

        Assert.assertNull(a.getExtensions());
        Assert.assertNull(b.getExtensions());
    }

    void testCreationOptions(@Nullable Long timeout) {
        byte[] userId = new byte[4 + random.nextInt(29)];
        byte[] challenge = new byte[32];
        random.nextBytes(userId);
        random.nextBytes(challenge);

        List<PublicKeyCredentialParameters> pubKeyCredParams = new ArrayList<>(
                Arrays.asList(
                        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7),
                        new PublicKeyCredentialParameters("unknown public key type", -7)
                )
        );

        List<PublicKeyCredentialDescriptor> excludeCredentials = new ArrayList<>(
                Arrays.asList(
                        new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, userId, null),
                        new PublicKeyCredentialDescriptor("unknown public key type", userId, null)
                )
        );

        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity("Example", "example.com"),
                new PublicKeyCredentialUserEntity("user", userId, "A User Name"),
                challenge,
                pubKeyCredParams,
                timeout,
                excludeCredentials,
                new AuthenticatorSelectionCriteria(null, ResidentKeyRequirement.REQUIRED, null),
                AttestationConveyancePreference.INDIRECT,
                null
        );

        compareCreationOptions(options, PublicKeyCredentialCreationOptions.fromMap(options.toMap()));
    }

    @Test
    public void testCreationOptions() {
        testCreationOptions((long) random.nextInt(Integer.MAX_VALUE));
        testCreationOptions(null);
    }

    private void compareRequestOptions(PublicKeyCredentialRequestOptions a, PublicKeyCredentialRequestOptions b) {
        Assert.assertArrayEquals(a.getChallenge(), b.getChallenge());
        Assert.assertEquals(a.getTimeout(), b.getTimeout());
        Assert.assertEquals(a.getRpId(), b.getRpId());
        compareDescriptorLists(a.getAllowCredentials(), b.getAllowCredentials());
        Assert.assertEquals(a.getUserVerification(), b.getUserVerification());

        Assert.assertNull(a.getExtensions());
        Assert.assertNull(b.getExtensions());
    }

    public void testRequestOptions(@Nullable Long timeout) {
        byte[] challenge = new byte[32];
        byte[] credentialId = new byte[1 + random.nextInt(128)];
        random.nextBytes(challenge);
        random.nextBytes(credentialId);

        List<PublicKeyCredentialDescriptor> allowCredentials = new ArrayList<>(
                Arrays.asList(
                new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credentialId, null),
                new PublicKeyCredentialDescriptor("unknown public key type", credentialId, null))
        );

        PublicKeyCredentialRequestOptions options = new PublicKeyCredentialRequestOptions(
                challenge,
                timeout,
                "example.com",
                allowCredentials,
                UserVerificationRequirement.REQUIRED,
                null
        );

        compareRequestOptions(options, PublicKeyCredentialRequestOptions.fromMap(options.toMap()));
    }

    @Test
    public void testRequestOptions() {
        testRequestOptions((long) random.nextInt(Integer.MAX_VALUE));
        testRequestOptions(null);
    }

    private void compareAssertions(AuthenticatorAssertionResponse a, AuthenticatorAssertionResponse b) {
        Assert.assertArrayEquals(a.getAuthenticatorData(), b.getAuthenticatorData());
        Assert.assertArrayEquals(a.getSignature(), b.getSignature());
        Assert.assertArrayEquals(a.getUserHandle(), b.getUserHandle());
        Assert.assertArrayEquals(a.getClientDataJson(), b.getClientDataJson());
    }

    private AuthenticatorAssertionResponse randomAuthenticatorAssertionResponse() {
        byte[] authData = new byte[128];
        random.nextBytes(authData);
        byte[] credentialId = new byte[1 + random.nextInt(64)];
        random.nextBytes(credentialId);
        byte[] signature = new byte[70];
        random.nextBytes(signature);
        byte[] userId = new byte[1 + random.nextInt(64)];
        random.nextBytes(userId);
        byte[] clientDataJson = new byte[64 + random.nextInt(64)];
        random.nextBytes(clientDataJson);

        return new AuthenticatorAssertionResponse(
                clientDataJson,
                authData,
                signature,
                userId
        );
    }

    @Test
    public void testAssertionResponse() {
        AuthenticatorAssertionResponse response = randomAuthenticatorAssertionResponse();
        compareAssertions(response, AuthenticatorAssertionResponse.fromMap(response.toMap()));
    }

    private void compareAttestations(AuthenticatorAttestationResponse a, AuthenticatorAttestationResponse b) {
        Assert.assertArrayEquals(a.getAttestationObject(), b.getAttestationObject());
        Assert.assertArrayEquals(a.getClientDataJson(), b.getClientDataJson());
    }

    AuthenticatorAttestationResponse randomAuthenticatorAttestationResponse() {
        byte[] attestationObject = new byte[128 + random.nextInt(128)];
        random.nextBytes(attestationObject);
        byte[] clientDataJson = new byte[64 + random.nextInt(64)];
        random.nextBytes(clientDataJson);

        return new AuthenticatorAttestationResponse(
                clientDataJson,
                attestationObject
        );
    }

    @Test
    public void testAttestationResponse() {
        AuthenticatorAttestationResponse response = randomAuthenticatorAttestationResponse();
        compareAttestations(response, AuthenticatorAttestationResponse.fromMap(response.toMap()));
    }

    void comparePublicKeyCredentialsWithAttestation(PublicKeyCredential a, PublicKeyCredential b) {
        Assert.assertArrayEquals(a.getRawId(), b.getRawId());
        Assert.assertEquals(a.getId(), b.getId());
        compareAttestations(
                (AuthenticatorAttestationResponse) a.getResponse(),
                (AuthenticatorAttestationResponse) b.getResponse()
        );
    }

    void comparePublicKeyCredentialsWithAssertion(PublicKeyCredential a, PublicKeyCredential b) {
        Assert.assertArrayEquals(a.getRawId(), b.getRawId());
        Assert.assertEquals(a.getId(), b.getId());
        compareAssertions(
                (AuthenticatorAssertionResponse) a.getResponse(),
                (AuthenticatorAssertionResponse) b.getResponse()
        );
    }

    @Test
    public void testPublicKeyCredentialCreation() {
        byte[] credentialId = new byte[1 + random.nextInt(64)];
        random.nextBytes(credentialId);
        String credentialIdB64UrlEncoded = Base64.encodeBase64URLSafeString(credentialId);

        AuthenticatorAttestationResponse response = randomAuthenticatorAttestationResponse();

        // credentialId as String
        PublicKeyCredential credential = new PublicKeyCredential(
                credentialIdB64UrlEncoded,
                response
        );

        Assert.assertEquals(credentialIdB64UrlEncoded, credential.getId());
        Assert.assertArrayEquals(credentialId, credential.getRawId());
        Assert.assertEquals(PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, credential.getType());

        // credentialId as byte[]
        PublicKeyCredential credential2 = new PublicKeyCredential(
                credentialId,
                response
        );

        Assert.assertEquals(credentialIdB64UrlEncoded, credential2.getId());
        Assert.assertArrayEquals(credentialId, credential2.getRawId());
        Assert.assertEquals(PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, credential2.getType());
    }

    @Test
    public void testPublicKeyCredentialWithAssertion() {
        byte[] credentialId = new byte[1 + random.nextInt(64)];
        random.nextBytes(credentialId);
        String credentialIdB64UrlEncoded = Base64.encodeBase64URLSafeString(credentialId);

        AuthenticatorAssertionResponse response = randomAuthenticatorAssertionResponse();

        PublicKeyCredential credential = new PublicKeyCredential(
                credentialIdB64UrlEncoded,
                response
        );

        Assert.assertEquals(credentialIdB64UrlEncoded, credential.getId());
        Assert.assertArrayEquals(credentialId, credential.getRawId());
        Assert.assertEquals(PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, credential.getType());

        comparePublicKeyCredentialsWithAssertion(credential, PublicKeyCredential.fromMap(credential.toMap()));
    }

    @Test
    public void testPublicKeyCredentialWithAttestation() {
        byte[] credentialId = new byte[1 + random.nextInt(64)];
        random.nextBytes(credentialId);
        String credentialIdB64UrlEncoded = Base64.encodeBase64URLSafeString(credentialId);

        AuthenticatorAttestationResponse response = randomAuthenticatorAttestationResponse();

        PublicKeyCredential credential = new PublicKeyCredential(
                credentialIdB64UrlEncoded,
                response
        );

        Assert.assertEquals(credentialIdB64UrlEncoded, credential.getId());
        Assert.assertArrayEquals(credentialId, credential.getRawId());
        Assert.assertEquals(PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, credential.getType());

        comparePublicKeyCredentialsWithAttestation(credential, PublicKeyCredential.fromMap(credential.toMap()));
    }

}

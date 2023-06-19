/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.webauthn;

import com.yubico.yubikit.fido.Cbor;

import org.junit.Assert;
import org.junit.Test;

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;

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
    @SuppressWarnings("unchecked")
    public void testRpEntity() {
        PublicKeyCredentialRpEntity rp = new PublicKeyCredentialRpEntity(
                "An Example Company", "example.com"
        );

        Map<String, ?> map = rp.toMap();

        Assert.assertEquals(rp.getId(), map.get("id"));
        Assert.assertEquals(rp.getName(), map.get("name"));

        compareRpEntities(rp, PublicKeyCredentialRpEntity.fromMap(map));
        compareRpEntities(rp, PublicKeyCredentialRpEntity.fromMap((Map<String, ?>) Cbor.decode(Cbor.encode(map))));
    }

    private void compareUserEntities(PublicKeyCredentialUserEntity a, PublicKeyCredentialUserEntity b) {
        Assert.assertArrayEquals(a.getId(), b.getId());
        Assert.assertEquals(a.getName(), b.getName());
        Assert.assertEquals(a.getDisplayName(), b.getDisplayName());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testUserEntity() {
        byte[] userId = new byte[4 + random.nextInt(29)];
        random.nextBytes(userId);

        PublicKeyCredentialUserEntity user = new PublicKeyCredentialUserEntity(
                "user@example.com", userId,
                "A. User"
        );

        Map<String, ?> map = user.toMap();

        Assert.assertEquals(user.getId(), map.get("id"));
        Assert.assertEquals(user.getName(), map.get("name"));
        Assert.assertEquals(user.getDisplayName(), map.get("displayName"));

        compareUserEntities(user, PublicKeyCredentialUserEntity.fromMap(map));
        compareUserEntities(user, PublicKeyCredentialUserEntity.fromMap((Map<String, ?>) Cbor.decode(Cbor.encode(map))));
    }

    private void compareParameters(PublicKeyCredentialParameters a, PublicKeyCredentialParameters b) {
        Assert.assertEquals(a.getType(), b.getType());
        Assert.assertEquals(a.getAlg(), b.getAlg());
    }

    private void compareParametersLists(List<PublicKeyCredentialParameters> a, List<PublicKeyCredentialParameters> b) {
        if (a == null && b == null) {
            return;
        }

        Assert.assertEquals(a.size(), b.size());
        for (int i = 0; i < a.size(); i++) {
            compareParameters(a.get(i), b.get(i));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testParameters() {
        PublicKeyCredentialParameters param = new PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                -7
        );

        Map<String, ?> map = param.toMap();

        Assert.assertEquals(param.getType().toString(), map.get("type"));
        Assert.assertEquals(param.getAlg(), map.get("alg"));

        compareParameters(param, PublicKeyCredentialParameters.fromMap(map));
        compareParameters(param, PublicKeyCredentialParameters.fromMap((Map<String, ?>) Cbor.decode(Cbor.encode(map))));
    }

    private void compareDescriptors(PublicKeyCredentialDescriptor a, PublicKeyCredentialDescriptor b) {
        Assert.assertEquals(a.getType(), b.getType());
        Assert.assertArrayEquals(a.getId(), b.getId());
        Assert.assertEquals(a.getTransports(), b.getTransports());
    }

    private void compareDescriptorLists(List<PublicKeyCredentialDescriptor> a, List<PublicKeyCredentialDescriptor> b) {
        if (a == null && b == null) {
            return;
        }

        Assert.assertEquals(a.size(), b.size());
        for (int i = 0; i < a.size(); i++) {
            compareDescriptors(a.get(i), b.get(i));
        }
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testDescriptor() {
        byte[] credentialId = new byte[4 + random.nextInt(29)];
        random.nextBytes(credentialId);

        PublicKeyCredentialDescriptor descriptor = new PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY,
                credentialId,
                Arrays.asList("USB", "NFC")
        );

        Map<String, ?> map = descriptor.toMap();

        Assert.assertEquals(descriptor.getType().toString(), map.get("type"));
        Assert.assertArrayEquals(descriptor.getId(), (byte[]) map.get("id"));

        compareDescriptors(descriptor, PublicKeyCredentialDescriptor.fromMap(map));
        compareDescriptors(descriptor, PublicKeyCredentialDescriptor.fromMap((Map<String, ?>) Cbor.decode(Cbor.encode(map))));
    }

    private void compareSelectionCritiera(AuthenticatorSelectionCriteria a, AuthenticatorSelectionCriteria b) {
        if (a == null && b == null) {
            return;
        }
        Assert.assertEquals(a.getAuthenticatorAttachment(), b.getAuthenticatorAttachment());
        Assert.assertEquals(a.getResidentKey(), b.getResidentKey());
        Assert.assertEquals(a.isRequireResidentKey(), b.isRequireResidentKey());
        Assert.assertEquals(a.getUserVerification(), b.getUserVerification());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testSelectionCriteria() {
        AuthenticatorSelectionCriteria criteria = new AuthenticatorSelectionCriteria(
                AuthenticatorAttachment.PLATFORM,
                ResidentKeyRequirement.REQUIRED,
                UserVerificationRequirement.PREFERRED
        );

        Map<String, ?> map = criteria.toMap();

        Assert.assertEquals(criteria.getAuthenticatorAttachment().toString(), map.get("authenticatorAttachment"));
        Assert.assertEquals(criteria.getUserVerification().toString(), map.get("userVerification"));
        Assert.assertEquals(criteria.getResidentKey().toString(), map.get("residentKey"));
        Assert.assertTrue(criteria.isRequireResidentKey());

        compareSelectionCritiera(criteria, AuthenticatorSelectionCriteria.fromMap(map));
        compareSelectionCritiera(criteria, AuthenticatorSelectionCriteria.fromMap((Map<String, ?>) Cbor.decode(Cbor.encode(map))));
    }

    private void compareCreationOptions(PublicKeyCredentialCreationOptions a, PublicKeyCredentialCreationOptions b) {
        compareRpEntities(a.getRp(), b.getRp());
        compareUserEntities(a.getUser(), b.getUser());
        Assert.assertArrayEquals(a.getChallenge(), b.getChallenge());
        compareParametersLists(a.getPubKeyCredParams(), b.getPubKeyCredParams());
        Assert.assertEquals(a.getTimeout(), b.getTimeout());
        compareDescriptorLists(a.getExcludeCredentials(), b.getExcludeCredentials());
        compareSelectionCritiera(a.getAuthenticatorSelection(), b.getAuthenticatorSelection());
        Assert.assertEquals(a.getAttestation(), b.getAttestation());

        Assert.assertNull(a.getExtensions());
        Assert.assertNull(b.getExtensions());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testCreationOptions() {
        byte[] userId = new byte[4 + random.nextInt(29)];
        byte[] challenge = new byte[32];
        random.nextBytes(userId);
        random.nextBytes(challenge);

        PublicKeyCredentialCreationOptions options = new PublicKeyCredentialCreationOptions(
                new PublicKeyCredentialRpEntity("Example", "example.com"),
                new PublicKeyCredentialUserEntity("user", userId, "A User Name"),
                challenge,
                Collections.singletonList(new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7)),
                random.nextInt(Integer.MAX_VALUE),
                Collections.singletonList(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, userId, null)),
                new AuthenticatorSelectionCriteria(null, ResidentKeyRequirement.REQUIRED, null),
                AttestationConveyancePreference.INDIRECT,
                null
        );

        Map<String, ?> map = options.toMap();

        compareCreationOptions(options, PublicKeyCredentialCreationOptions.fromMap(map));
        compareCreationOptions(options, PublicKeyCredentialCreationOptions.fromMap((Map<String, ?>) Cbor.decode(Cbor.encode(map))));
        compareCreationOptions(options, PublicKeyCredentialCreationOptions.fromBytes(options.toBytes()));
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

    @Test
    @SuppressWarnings("unchecked")
    public void testRequestOptions() {
        byte[] challenge = new byte[32];
        byte[] credentialId = new byte[1 + random.nextInt(128)];
        random.nextBytes(challenge);
        random.nextBytes(credentialId);

        PublicKeyCredentialRequestOptions options = new PublicKeyCredentialRequestOptions(
                challenge,
                random.nextInt(Integer.MAX_VALUE),
                "example.com",
                Collections.singletonList(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credentialId, null)),
                UserVerificationRequirement.REQUIRED,
                null
        );

        Map<String, ?> map = options.toMap();

        compareRequestOptions(options, PublicKeyCredentialRequestOptions.fromMap(map));
        compareRequestOptions(options, PublicKeyCredentialRequestOptions.fromMap((Map<String, ?>) Cbor.decode(Cbor.encode(map))));
        compareRequestOptions(options, PublicKeyCredentialRequestOptions.fromBytes(options.toBytes()));
    }

    private void compareAssertions(AuthenticatorAssertionResponse a, AuthenticatorAssertionResponse b) {
        Assert.assertArrayEquals(a.getAuthenticatorData(), b.getAuthenticatorData());
        Assert.assertArrayEquals(a.getCredentialId(), b.getCredentialId());
        Assert.assertArrayEquals(a.getSignature(), b.getSignature());
        Assert.assertArrayEquals(a.getUserHandle(), b.getUserHandle());
        Assert.assertArrayEquals(a.getClientDataJson(), b.getClientDataJson());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testAssertionResponse() {
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

        AuthenticatorAssertionResponse response = new AuthenticatorAssertionResponse(
                authData,
                clientDataJson,
                signature,
                userId,
                credentialId
        );

        Map<String, ?> map = response.toMap();

        compareAssertions(response, AuthenticatorAssertionResponse.fromMap(map));
        compareAssertions(response, AuthenticatorAssertionResponse.fromMap((Map<String, ?>) Cbor.decode(Cbor.encode(map))));
        compareAssertions(response, AuthenticatorAssertionResponse.fromBytes(response.toBytes()));
    }

    private void compareAttestations(AuthenticatorAttestationResponse a, AuthenticatorAttestationResponse b) {
        Assert.assertArrayEquals(a.getAttestationObject(), b.getAttestationObject());
        Assert.assertArrayEquals(a.getClientDataJson(), b.getClientDataJson());
    }

    @Test
    @SuppressWarnings("unchecked")
    public void testAttestationResponse() {
        byte[] attestationObject = new byte[128 + random.nextInt(128)];
        random.nextBytes(attestationObject);
        byte[] clientDataJson = new byte[64 + random.nextInt(64)];
        random.nextBytes(clientDataJson);

        AuthenticatorAttestationResponse response = new AuthenticatorAttestationResponse(
                attestationObject,
                clientDataJson
        );

        Map<String, ?> map = response.toMap();

        compareAttestations(response, AuthenticatorAttestationResponse.fromMap(map));
        compareAttestations(response, AuthenticatorAttestationResponse.fromMap((Map<String, ?>) Cbor.decode(Cbor.encode(map))));
        compareAttestations(response, AuthenticatorAttestationResponse.fromBytes(response.toBytes()));
    }
}

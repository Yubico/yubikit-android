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

package com.yubico.yubikit.fido.webauthn;

import com.yubico.yubikit.core.internal.codec.Base64;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Assert;
import org.junit.Test;

/**
 * Test serialization and deserialization of WebAuthn data objects using toMap/fromMap as well as
 * toBytes/fromBytes where applicable. Also tests that each object can successfully serialize to and
 * from CBOR.
 */
public class SerializationTest {
  private final SecureRandom random = new SecureRandom();

  @Test
  public void testRpEntity() {
    PublicKeyCredentialRpEntity rp =
        new PublicKeyCredentialRpEntity("An Example Company", "example.com");

    Map<String, ?> map = rp.toMap(SerializationType.CBOR);

    Assert.assertEquals(rp.getId(), map.get("id"));
    Assert.assertEquals(rp.getName(), map.get("name"));

    Assert.assertEquals(rp, PublicKeyCredentialRpEntity.fromMap(map, SerializationType.CBOR));
  }

  @Test
  public void testUserEntity() {
    byte[] userId = new byte[4 + random.nextInt(29)];
    random.nextBytes(userId);

    PublicKeyCredentialUserEntity user =
        new PublicKeyCredentialUserEntity("user@example.com", userId, "A. User");

    Map<String, ?> cborMap = user.toMap(SerializationType.CBOR);
    Assert.assertEquals(user.getId(), cborMap.get("id"));
    Assert.assertEquals(user.getName(), cborMap.get("name"));
    Assert.assertEquals(user.getDisplayName(), cborMap.get("displayName"));
    Assert.assertEquals(
        user, PublicKeyCredentialUserEntity.fromMap(cborMap, SerializationType.CBOR));

    Map<String, ?> jsonMap = user.toMap(SerializationType.JSON);
    Assert.assertEquals(Base64.toUrlSafeString(user.getId()), jsonMap.get("id"));
    Assert.assertEquals(user.getName(), jsonMap.get("name"));
    Assert.assertEquals(user.getDisplayName(), jsonMap.get("displayName"));
    Assert.assertEquals(
        user, PublicKeyCredentialUserEntity.fromMap(jsonMap, SerializationType.JSON));
  }

  private void compareParametersLists(
      List<PublicKeyCredentialParameters> a, List<PublicKeyCredentialParameters> b) {
    Assert.assertEquals(a.size(), b.size());
    for (int i = 0; i < a.size(); i++) {
      Assert.assertEquals(a.get(i), b.get(i));
    }
  }

  @Test
  public void testParameters() {
    PublicKeyCredentialParameters param =
        new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7);

    Map<String, ?> map = param.toMap(SerializationType.CBOR);

    Assert.assertEquals(param.getType(), map.get("type"));
    Assert.assertEquals(param.getAlg(), map.get("alg"));

    Assert.assertEquals(param, PublicKeyCredentialParameters.fromMap(map, SerializationType.CBOR));
  }

  private void compareDescriptorLists(
      List<PublicKeyCredentialDescriptor> a, List<PublicKeyCredentialDescriptor> b) {
    Assert.assertEquals(a.size(), b.size());
    for (int i = 0; i < a.size(); i++) {
      Assert.assertEquals(a.get(i), b.get(i));
    }
  }

  @Test
  public void testDescriptor() {
    byte[] credentialId = new byte[4 + random.nextInt(29)];
    random.nextBytes(credentialId);

    PublicKeyCredentialDescriptor descriptor =
        new PublicKeyCredentialDescriptor(
            PublicKeyCredentialType.PUBLIC_KEY, credentialId, Arrays.asList("USB", "NFC"));

    Map<String, ?> cborMap = descriptor.toMap(SerializationType.CBOR);
    Assert.assertEquals(descriptor.getType(), cborMap.get("type"));
    Assert.assertArrayEquals(descriptor.getId(), (byte[]) cborMap.get("id"));
    Assert.assertEquals(
        descriptor, PublicKeyCredentialDescriptor.fromMap(cborMap, SerializationType.CBOR));

    Map<String, ?> jsonMap = descriptor.toMap(SerializationType.JSON);
    Assert.assertEquals(descriptor.getType(), jsonMap.get("type"));
    Assert.assertEquals(Base64.toUrlSafeString(descriptor.getId()), jsonMap.get("id"));
    Assert.assertEquals(
        descriptor, PublicKeyCredentialDescriptor.fromMap(jsonMap, SerializationType.JSON));
  }

  @Test
  public void testSelectionCriteria() {
    AuthenticatorSelectionCriteria criteria =
        new AuthenticatorSelectionCriteria(
            AuthenticatorAttachment.PLATFORM,
            ResidentKeyRequirement.REQUIRED,
            UserVerificationRequirement.PREFERRED);

    Map<String, ?> map = criteria.toMap(SerializationType.CBOR);

    Assert.assertNotNull(criteria.getAuthenticatorAttachment());
    Assert.assertNotNull(criteria.getResidentKey());
    Assert.assertEquals(criteria.getAuthenticatorAttachment(), map.get("authenticatorAttachment"));
    Assert.assertEquals(criteria.getUserVerification(), map.get("userVerification"));
    Assert.assertEquals(criteria.getResidentKey(), map.get("residentKey"));

    Assert.assertEquals(
        criteria, AuthenticatorSelectionCriteria.fromMap(map, SerializationType.CBOR));
  }

  private void compareCreationOptions(
      PublicKeyCredentialCreationOptions a, PublicKeyCredentialCreationOptions b) {
    Assert.assertEquals(a.getRp(), b.getRp());
    Assert.assertEquals(a.getUser(), b.getUser());
    Assert.assertArrayEquals(a.getChallenge(), b.getChallenge());
    compareParametersLists(a.getPubKeyCredParams(), b.getPubKeyCredParams());
    Assert.assertEquals(a.getTimeout(), b.getTimeout());
    compareDescriptorLists(a.getExcludeCredentials(), b.getExcludeCredentials());
    Assert.assertEquals(a.getAuthenticatorSelection(), b.getAuthenticatorSelection());
    Assert.assertEquals(a.getAttestation(), b.getAttestation());
    Assert.assertEquals(a.getExtensions(), b.getExtensions());
  }

  void testCreationOptions(@Nullable Long timeout) {
    byte[] userId = new byte[4 + random.nextInt(29)];
    byte[] challenge = new byte[32];
    random.nextBytes(userId);
    random.nextBytes(challenge);

    List<PublicKeyCredentialParameters> pubKeyCredParams =
        new ArrayList<>(
            Arrays.asList(
                new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7),
                new PublicKeyCredentialParameters("unknown public key type", -7)));

    List<PublicKeyCredentialDescriptor> excludeCredentials =
        new ArrayList<>(
            Arrays.asList(
                new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, userId, null),
                new PublicKeyCredentialDescriptor("unknown public key type", userId, null)));

    PublicKeyCredentialCreationOptions options =
        new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("Example", "example.com"),
            new PublicKeyCredentialUserEntity("user", userId, "A User Name"),
            challenge,
            pubKeyCredParams,
            timeout,
            excludeCredentials,
            new AuthenticatorSelectionCriteria(null, ResidentKeyRequirement.REQUIRED, null),
            AttestationConveyancePreference.INDIRECT,
            null);

    compareCreationOptions(
        options,
        PublicKeyCredentialCreationOptions.fromMap(
            options.toMap(SerializationType.CBOR), SerializationType.CBOR));

    compareCreationOptions(
        options,
        PublicKeyCredentialCreationOptions.fromMap(
            options.toMap(SerializationType.JSON), SerializationType.JSON));
  }

  @Test
  public void testCreationOptions() {
    testCreationOptions((long) random.nextInt(Integer.MAX_VALUE));
    testCreationOptions(null);
  }

  public void testRequestOptions(@Nullable Long timeout) {
    byte[] challenge = new byte[32];
    byte[] credentialId = new byte[1 + random.nextInt(128)];
    random.nextBytes(challenge);
    random.nextBytes(credentialId);

    PublicKeyCredentialRequestOptions options =
        new PublicKeyCredentialRequestOptions(
            challenge,
            timeout,
            "example.com",
            new ArrayList<>(
                Arrays.asList(
                    new PublicKeyCredentialDescriptor(
                        PublicKeyCredentialType.PUBLIC_KEY, credentialId, null),
                    new PublicKeyCredentialDescriptor(
                        "unknown public key type", credentialId, null))),
            UserVerificationRequirement.REQUIRED,
            null);

    Assert.assertEquals(
        options,
        PublicKeyCredentialRequestOptions.fromMap(
            options.toMap(SerializationType.JSON), SerializationType.JSON));

    Assert.assertEquals(
        options,
        PublicKeyCredentialRequestOptions.fromMap(
            options.toMap(SerializationType.CBOR), SerializationType.CBOR));
  }

  @Test
  public void testRequestOptions() {
    testRequestOptions((long) random.nextInt(Integer.MAX_VALUE));
    testRequestOptions(null);
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

    return new AuthenticatorAssertionResponse(clientDataJson, authData, signature, userId);
  }

  @Test
  public void testAssertionResponse() {
    AuthenticatorAssertionResponse response = randomAuthenticatorAssertionResponse();

    Assert.assertEquals(
        response,
        AuthenticatorAssertionResponse.fromMap(
            response.toMap(SerializationType.CBOR), SerializationType.CBOR));

    Assert.assertEquals(
        response,
        AuthenticatorAssertionResponse.fromMap(
            response.toMap(SerializationType.JSON), SerializationType.JSON));
  }

  AuthenticatorAttestationResponse randomAuthenticatorAttestationResponse() {
    byte[] attestationObject = new byte[128 + random.nextInt(128)];
    random.nextBytes(attestationObject);
    byte[] clientDataJson = new byte[64 + random.nextInt(64)];
    random.nextBytes(clientDataJson);
    List<String> transports = Arrays.asList("nfc", "usb");

    @SuppressWarnings("SpellCheckingInspection")
    AuthenticatorData authenticatorData =
        AuthenticatorData.parseFrom(
            ByteBuffer.wrap(
                Base64.fromUrlSafeString(
                    "5Yaf4EYzO6ALp_K7s-p-BQLPSCYVYcKLZptoXwxqQztFAAAAAhSaICGO9kEzlriB-NW38fUAMA5hR"
                        + "7Wj16h_z28qvtukB63QcIhzJ_sUkkJPfsU-KzdCFeaF2mZ80gSROEtELSHniKUBAgMmIAEh"
                        + "WCAOYUe1o9eof89vKr7bLZhH7nLY4wjKx5oxa66Kv0JjXiJYIKyPUlRxXHJjLrACafd_1st"
                        + "M7DyX120jDO7BlwqYsJyJ")));

    return new AuthenticatorAttestationResponse(
        clientDataJson, authenticatorData, transports, null, 0, attestationObject);
  }

  @Test
  public void testAttestationResponse() {
    AuthenticatorAttestationResponse response = randomAuthenticatorAttestationResponse();
    Assert.assertEquals(
        response,
        AuthenticatorAttestationResponse.fromMap(
            response.toMap(SerializationType.CBOR), SerializationType.CBOR));

    Assert.assertEquals(
        response,
        AuthenticatorAttestationResponse.fromMap(
            response.toMap(SerializationType.JSON), SerializationType.JSON));
  }

  @Test
  public void testPublicKeyCredentialCreation() {
    byte[] credentialId = new byte[1 + random.nextInt(64)];
    random.nextBytes(credentialId);
    String credentialIdB64UrlEncoded = Base64.toUrlSafeString(credentialId);

    AuthenticatorAttestationResponse response = randomAuthenticatorAttestationResponse();

    // credentialId as String
    PublicKeyCredential credential = new PublicKeyCredential(credentialIdB64UrlEncoded, response);

    Assert.assertEquals(credentialIdB64UrlEncoded, credential.getId());
    Assert.assertArrayEquals(credentialId, credential.getRawId());
    Assert.assertEquals(PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, credential.getType());

    // credentialId as byte[]
    PublicKeyCredential credential2 = new PublicKeyCredential(credentialId, response);

    Assert.assertEquals(credentialIdB64UrlEncoded, credential2.getId());
    Assert.assertArrayEquals(credentialId, credential2.getRawId());
    Assert.assertEquals(PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, credential2.getType());
  }

  @Test
  public void testPublicKeyCredentialWithAssertion() {
    byte[] credentialId = new byte[1 + random.nextInt(64)];
    random.nextBytes(credentialId);
    String credentialIdB64UrlEncoded = Base64.toUrlSafeString(credentialId);

    AuthenticatorAssertionResponse response = randomAuthenticatorAssertionResponse();

    PublicKeyCredential credential = new PublicKeyCredential(credentialIdB64UrlEncoded, response);

    Assert.assertEquals(credentialIdB64UrlEncoded, credential.getId());
    Assert.assertArrayEquals(credentialId, credential.getRawId());
    Assert.assertEquals(PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, credential.getType());

    Assert.assertEquals(
        credential,
        PublicKeyCredential.fromMap(
            credential.toMap(SerializationType.CBOR), SerializationType.CBOR));

    Assert.assertEquals(
        credential,
        PublicKeyCredential.fromMap(
            credential.toMap(SerializationType.JSON), SerializationType.JSON));
  }

  @Test
  public void testPublicKeyCredentialWithAttestation() {
    byte[] credentialId = new byte[1 + random.nextInt(64)];
    random.nextBytes(credentialId);
    String credentialIdB64UrlEncoded = Base64.toUrlSafeString(credentialId);

    AuthenticatorAttestationResponse response = randomAuthenticatorAttestationResponse();

    PublicKeyCredential credential = new PublicKeyCredential(credentialIdB64UrlEncoded, response);

    Assert.assertEquals(credentialIdB64UrlEncoded, credential.getId());
    Assert.assertArrayEquals(credentialId, credential.getRawId());
    Assert.assertEquals(PublicKeyCredential.PUBLIC_KEY_CREDENTIAL_TYPE, credential.getType());

    Assert.assertEquals(
        credential,
        PublicKeyCredential.fromMap(
            credential.toMap(SerializationType.CBOR), SerializationType.CBOR));

    Assert.assertEquals(
        credential,
        PublicKeyCredential.fromMap(
            credential.toMap(SerializationType.JSON), SerializationType.JSON));
  }
}

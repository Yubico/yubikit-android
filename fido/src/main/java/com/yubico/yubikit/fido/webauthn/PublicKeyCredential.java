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

import static com.yubico.yubikit.fido.webauthn.SerializationUtils.serializeBytes;

import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

public class PublicKeyCredential extends Credential {
  public static final String RAW_ID = "rawId";
  public static final String RESPONSE = "response";
  public static final String AUTHENTICATOR_ATTACHMENT = "authenticatorAttachment";
  public static final String CLIENT_EXTENSION_RESULTS = "clientExtensionResults";

  public static final String PUBLIC_KEY_CREDENTIAL_TYPE = "public-key";

  private final byte[] rawId;
  private final AuthenticatorResponse response;
  @Nullable private final ClientExtensionResults clientExtensionResults;

  /**
   * Constructs a new Webauthn PublicKeyCredential object
   *
   * @param id Credential id in base64 url safe encoding.
   * @param response Operation response.
   * @see AuthenticatorAttestationResponse
   * @see AuthenticatorAssertionResponse
   */
  public PublicKeyCredential(String id, AuthenticatorResponse response) {
    this(id, response, null);
  }

  /**
   * Constructs a new Webauthn PublicKeyCredential object
   *
   * @param id Credential id in base64 url safe encoding.
   * @param response Operation response.
   * @param clientExtensionResults Extension results.
   * @see AuthenticatorAttestationResponse
   * @see AuthenticatorAssertionResponse
   */
  public PublicKeyCredential(
      String id,
      AuthenticatorResponse response,
      @Nullable ClientExtensionResults clientExtensionResults) {
    super(id, PUBLIC_KEY_CREDENTIAL_TYPE);
    this.rawId = Base64.fromUrlSafeString(id);
    this.response = response;
    this.clientExtensionResults = clientExtensionResults;
  }

  /**
   * Constructs a new Webauthn PublicKeyCredential object
   *
   * @param id Credential id in binary form.
   * @param response Operation response.
   * @see AuthenticatorAttestationResponse
   * @see AuthenticatorAssertionResponse
   */
  public PublicKeyCredential(byte[] id, AuthenticatorResponse response) {
    this(id, response, null);
  }

  /**
   * Constructs a new Webauthn PublicKeyCredential object
   *
   * @param id Credential id in binary form.
   * @param response Operation response.
   * @param clientExtensionResults Extension results.
   * @see AuthenticatorAttestationResponse
   * @see AuthenticatorAssertionResponse
   */
  public PublicKeyCredential(
      byte[] id,
      AuthenticatorResponse response,
      @Nullable ClientExtensionResults clientExtensionResults) {
    super(Base64.toUrlSafeString(id), PUBLIC_KEY_CREDENTIAL_TYPE);
    this.rawId = id;
    this.response = response;
    this.clientExtensionResults = clientExtensionResults;
  }

  public byte[] getRawId() {
    return Arrays.copyOf(rawId, rawId.length);
  }

  public AuthenticatorResponse getResponse() {
    return response;
  }

  @Nullable
  public ClientExtensionResults getClientExtensionResults() {
    return clientExtensionResults;
  }

  public Map<String, ?> toMap(SerializationType serializationType) {
    Map<String, Object> map = new HashMap<>();
    map.put(ID, getId());
    map.put(TYPE, getType());
    map.put(RAW_ID, serializeBytes(getRawId(), serializationType));
    map.put(AUTHENTICATOR_ATTACHMENT, AuthenticatorAttachment.CROSS_PLATFORM);
    map.put(RESPONSE, getResponse().toMap(serializationType));
    if (getClientExtensionResults() != null) {
      map.put(CLIENT_EXTENSION_RESULTS, getClientExtensionResults().toMap(serializationType));
    }
    return map;
  }

  public Map<String, ?> toMap() {
    return toMap(SerializationType.DEFAULT);
  }

  @SuppressWarnings("unchecked")
  public static PublicKeyCredential fromMap(
      Map<String, ?> map, SerializationType serializationType) {
    if (!PUBLIC_KEY_CREDENTIAL_TYPE.equals(Objects.requireNonNull((String) map.get(TYPE)))) {
      throw new IllegalArgumentException("Expecting type=" + PUBLIC_KEY_CREDENTIAL_TYPE);
    }

    Map<String, ?> responseMap = Objects.requireNonNull((Map<String, ?>) map.get(RESPONSE));
    AuthenticatorResponse response;
    try {
      if (responseMap.containsKey(AuthenticatorAttestationResponse.ATTESTATION_OBJECT)) {
        response = AuthenticatorAttestationResponse.fromMap(responseMap, serializationType);
      } else {
        response = AuthenticatorAssertionResponse.fromMap(responseMap, serializationType);
      }
    } catch (Exception e) {
      throw new IllegalArgumentException("Unknown AuthenticatorResponse format", e);
    }

    return new PublicKeyCredential(Objects.requireNonNull((String) map.get(ID)), response);
  }

  public static PublicKeyCredential fromMap(Map<String, ?> map) {
    return fromMap(map, SerializationType.DEFAULT);
  }

  /**
   * Constructs new PublicKeyCredential from AssertionData
   *
   * @param assertion Data base for the new credential.
   * @param clientDataJson Response client data.
   * @param allowCredentials Used for querying credential id for incomplete assertion objects
   * @return new PublicKeyCredential object.
   */
  public static PublicKeyCredential fromAssertion(
      Ctap2Session.AssertionData assertion,
      byte[] clientDataJson,
      @Nullable List<PublicKeyCredentialDescriptor> allowCredentials) {
    return fromAssertion(assertion, clientDataJson, allowCredentials, null);
  }

  /**
   * Constructs new PublicKeyCredential from AssertionData
   *
   * @param assertion Data base for the new credential.
   * @param clientDataJson Response client data.
   * @param allowCredentials Used for querying credential id for incomplete assertion objects.
   * @param clientExtensionResults Extension results.
   * @return new PublicKeyCredential object
   */
  public static PublicKeyCredential fromAssertion(
      Ctap2Session.AssertionData assertion,
      byte[] clientDataJson,
      @Nullable List<PublicKeyCredentialDescriptor> allowCredentials,
      @Nullable ClientExtensionResults clientExtensionResults) {
    byte[] userId = null;
    Map<String, ?> userMap = assertion.getUser();
    if (userMap != null) {
      // This is not a complete UserEntity object, it may contain only "id".
      userId = Objects.requireNonNull((byte[]) userMap.get(PublicKeyCredentialUserEntity.ID));
    }

    return new PublicKeyCredential(
        assertion.getCredentialId(allowCredentials),
        new AuthenticatorAssertionResponse(
            clientDataJson, assertion.getAuthenticatorData(), assertion.getSignature(), userId),
        clientExtensionResults);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    PublicKeyCredential that = (PublicKeyCredential) o;

    if (!Arrays.equals(rawId, that.rawId)) return false;
    return response.equals(that.response);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(rawId);
    result = 31 * result + response.hashCode();
    return result;
  }
}

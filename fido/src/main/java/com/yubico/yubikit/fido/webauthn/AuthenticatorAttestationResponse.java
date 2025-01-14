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

import static com.yubico.yubikit.fido.webauthn.SerializationUtils.deserializeBytes;
import static com.yubico.yubikit.fido.webauthn.SerializationUtils.serializeBytes;

import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.fido.Cose;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

public class AuthenticatorAttestationResponse extends AuthenticatorResponse {
  public static final String ATTESTATION_OBJECT = "attestationObject";
  public static final String TRANSPORTS = "transports";
  public static final String AUTHENTICATOR_DATA = "authenticatorData";
  public static final String PUBLIC_KEY = "publicKey";
  public static final String PUBLIC_KEY_ALGORITHM = "publicKeyAlgorithm";

  private final AuthenticatorData authenticatorData;
  private final List<String> transports;
  @Nullable private final byte[] publicKey;
  private final Integer publicKeyAlgorithm;
  private final byte[] attestationObject;

  private static final org.slf4j.Logger logger =
      LoggerFactory.getLogger(AuthenticatorAttestationResponse.class);

  public AuthenticatorAttestationResponse(
      byte[] clientDataJson,
      AuthenticatorData authenticatorData,
      List<String> transports,
      @Nullable byte[] publicKey,
      int publicKeyAlgorithm,
      byte[] attestationObject) {
    super(clientDataJson);
    this.transports = transports;
    this.attestationObject = attestationObject;

    this.authenticatorData = authenticatorData;
    this.publicKey = publicKey;
    this.publicKeyAlgorithm = publicKeyAlgorithm;
  }

  public AuthenticatorAttestationResponse(
      byte[] clientDataJson, List<String> transports, AttestationObject attestationObject) {
    super(clientDataJson);
    this.authenticatorData = attestationObject.getAuthenticatorData();
    this.transports = transports;
    this.attestationObject = attestationObject.toBytes();

    if (!authenticatorData.isAt()) {
      throw new IllegalArgumentException("Invalid attestation for makeCredential");
    }

    AttestedCredentialData attestedCredentialData =
        Objects.requireNonNull(authenticatorData.getAttestedCredentialData());

    // compute public key information
    Map<Integer, ?> cosePublicKey = attestedCredentialData.getCosePublicKey();
    this.publicKeyAlgorithm = Cose.getAlgorithm(cosePublicKey);
    byte[] resultPublicKey = null;
    try {
      PublicKey publicKey = Cose.getPublicKey(cosePublicKey);
      resultPublicKey = publicKey == null ? null : publicKey.getEncoded();
    } catch (InvalidKeySpecException | NoSuchAlgorithmException exception) {
      // library does not support this public key format
      Logger.info(
          logger,
          "Platform does not support binary serialization of the given key"
              + " type, the 'publicKey' field will be null.");
    }
    this.publicKey = resultPublicKey;
  }

  @SuppressWarnings("unused")
  public AuthenticatorData getAuthenticatorData() {
    return authenticatorData;
  }

  public List<String> getTransports() {
    return transports;
  }

  @Nullable
  @SuppressWarnings("unused")
  public byte[] getPublicKey() {
    return publicKey;
  }

  @SuppressWarnings("unused")
  public Integer getPublicKeyAlgorithm() {
    return publicKeyAlgorithm;
  }

  public byte[] getAttestationObject() {
    return attestationObject;
  }

  @Override
  public Map<String, ?> toMap(SerializationType serializationType) {
    Map<String, Object> map = new HashMap<>();
    map.put(CLIENT_DATA_JSON, serializeBytes(getClientDataJson(), serializationType));
    map.put(AUTHENTICATOR_DATA, serializeBytes(authenticatorData.getBytes(), serializationType));
    map.put(TRANSPORTS, transports);
    if (publicKey != null) {
      map.put(PUBLIC_KEY, serializeBytes(publicKey, serializationType));
    }
    map.put(PUBLIC_KEY_ALGORITHM, publicKeyAlgorithm);
    map.put(ATTESTATION_OBJECT, serializeBytes(attestationObject, serializationType));
    return map;
  }

  @SuppressWarnings("unchecked")
  public static AuthenticatorAttestationResponse fromMap(
      Map<String, ?> map, SerializationType serializationType) {
    Object publicKey = map.get(PUBLIC_KEY);
    return new AuthenticatorAttestationResponse(
        deserializeBytes(Objects.requireNonNull(map.get(CLIENT_DATA_JSON)), serializationType),
        AuthenticatorData.parseFrom(
            ByteBuffer.wrap(deserializeBytes(map.get(AUTHENTICATOR_DATA), serializationType))),
        (List<String>) Objects.requireNonNull(map.get(TRANSPORTS)),
        publicKey == null ? null : deserializeBytes(publicKey, serializationType),
        (Integer) map.get(PUBLIC_KEY_ALGORITHM),
        deserializeBytes(Objects.requireNonNull(map.get(ATTESTATION_OBJECT)), serializationType));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    AuthenticatorAttestationResponse that = (AuthenticatorAttestationResponse) o;

    if (!authenticatorData.equals(that.authenticatorData)) return false;
    if (!transports.equals(that.transports)) return false;
    if (!Arrays.equals(publicKey, that.publicKey)) return false;
    if (!publicKeyAlgorithm.equals(that.publicKeyAlgorithm)) return false;
    return Arrays.equals(attestationObject, that.attestationObject);
  }

  @Override
  public int hashCode() {
    int result = authenticatorData.hashCode();
    result = 31 * result + transports.hashCode();
    result = 31 * result + Arrays.hashCode(publicKey);
    result = 31 * result + publicKeyAlgorithm.hashCode();
    result = 31 * result + Arrays.hashCode(attestationObject);
    return result;
  }
}

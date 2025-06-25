/*
 * Copyright (C) 2023-2025 Yubico.
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

import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Webauthn AttestationObject which exposes attestation authenticator data.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation">WebAuthn
 *     Attestation</a>
 */
public class AttestationObject {
  public static final String KEY_FORMAT = "fmt";
  public static final String KEY_AUTHENTICATOR_DATA = "authData";
  public static final String KEY_ATTESTATION_STATEMENT = "attStmt";
  public static final String KEY_EP_ATT = "epAtt";
  public static final String KEY_LARGE_BLOB_KEY = "largeBlobKey";
  public static final String KEY_UNSIGNED_EXTENSION_OUTPUTS = "unsignedExtensionOutputs";

  private final String format;
  private final AuthenticatorData authenticatorData;
  private final Map<String, ?> attestationStatement;
  @Nullable private final Boolean enterpriseAttestation;
  @Nullable private final byte[] largeBlobKey;
  @Nullable private final Map<String, ?> unsignedExtensionOutputs;

  @Deprecated
  public AttestationObject(
      String format,
      AuthenticatorData authenticatorData,
      Map<String, ?> attestationStatement,
      @Nullable Boolean enterpriseAttestation,
      @Nullable byte[] largeBlobKey) {
    this(
        format, authenticatorData, attestationStatement, enterpriseAttestation, largeBlobKey, null);
  }

  public AttestationObject(
      String format,
      AuthenticatorData authenticatorData,
      Map<String, ?> attestationStatement,
      @Nullable Boolean enterpriseAttestation,
      @Nullable byte[] largeBlobKey,
      @Nullable Map<String, ?> unsignedExtensionOutputs) {
    this.format = format;
    this.authenticatorData = authenticatorData;
    this.attestationStatement = attestationStatement;
    this.enterpriseAttestation = enterpriseAttestation;
    this.largeBlobKey = largeBlobKey;
    this.unsignedExtensionOutputs = unsignedExtensionOutputs;
  }

  public static AttestationObject fromCredential(Ctap2Session.CredentialData credential) {
    return new AttestationObject(
        credential.getFormat(),
        AuthenticatorData.parseFrom(ByteBuffer.wrap(credential.getAuthenticatorData())),
        credential.getAttestationStatement(),
        credential.getEnterpriseAttestation(),
        credential.getLargeBlobKey(),
        credential.getUnsignedExtensionOutputs());
  }

  @SuppressWarnings("unused")
  public String getFormat() {
    return format;
  }

  public AuthenticatorData getAuthenticatorData() {
    return authenticatorData;
  }

  @SuppressWarnings("unused")
  public Map<String, ?> getAttestationStatement() {
    return attestationStatement;
  }

  @SuppressWarnings("unused")
  @Nullable
  public Boolean getEnterpriseAttestation() {
    return enterpriseAttestation;
  }

  @SuppressWarnings("unused")
  @Nullable
  public byte[] getLargeBlobKey() {
    return largeBlobKey;
  }

  @Nullable
  public Map<String, ?> getUnsignedExtensionOutputs() {
    return unsignedExtensionOutputs;
  }

  public byte[] toBytes() {
    Map<String, Object> attestationObject = new HashMap<>();
    attestationObject.put(AttestationObject.KEY_FORMAT, format);
    attestationObject.put(AttestationObject.KEY_AUTHENTICATOR_DATA, authenticatorData.getBytes());
    attestationObject.put(AttestationObject.KEY_ATTESTATION_STATEMENT, attestationStatement);
    if (enterpriseAttestation != null) {
      attestationObject.put(AttestationObject.KEY_EP_ATT, enterpriseAttestation);
    }
    if (largeBlobKey != null) {
      attestationObject.put(AttestationObject.KEY_LARGE_BLOB_KEY, largeBlobKey);
    }
    if (unsignedExtensionOutputs != null) {
      attestationObject.put(
          AttestationObject.KEY_UNSIGNED_EXTENSION_OUTPUTS, unsignedExtensionOutputs);
    }
    return Cbor.encode(attestationObject);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    AttestationObject that = (AttestationObject) o;

    if (!format.equals(that.format)) return false;
    if (!authenticatorData.equals(that.authenticatorData)) return false;
    if (!Objects.equals(enterpriseAttestation, that.enterpriseAttestation)) return false;
    if (!Arrays.equals(largeBlobKey, that.largeBlobKey)) return false;
    if (!Arrays.equals(Cbor.encode(attestationStatement), Cbor.encode(that.attestationStatement)))
      return false;
    if (unsignedExtensionOutputs != null && that.unsignedExtensionOutputs == null) return false;
    if (unsignedExtensionOutputs == null && that.unsignedExtensionOutputs != null) return false;
    return unsignedExtensionOutputs == null
        || (Arrays.equals(
            Cbor.encode(unsignedExtensionOutputs), Cbor.encode(that.unsignedExtensionOutputs)));
  }

  @Override
  public int hashCode() {
    int result = format.hashCode();
    result = 31 * result + authenticatorData.hashCode();
    result = 31 * result + Arrays.hashCode(Cbor.encode(attestationStatement));
    result = 31 * result + (enterpriseAttestation != null ? enterpriseAttestation.hashCode() : 0);
    result = 31 * result + Arrays.hashCode(largeBlobKey);
    result =
        31 * result
            + (unsignedExtensionOutputs != null
                ? Arrays.hashCode(Cbor.encode(unsignedExtensionOutputs))
                : 0);
    return result;
  }
}

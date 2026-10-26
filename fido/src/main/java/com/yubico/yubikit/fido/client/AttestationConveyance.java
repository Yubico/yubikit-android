/*
 * Copyright (C) 2026 Yubico.
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

import com.yubico.yubikit.fido.webauthn.AttestationConveyancePreference;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AttestedCredentialData;
import java.util.Collections;
import org.jspecify.annotations.Nullable;

/** Client side processing of the WebAuthn attestation conveyance preference. */
final class AttestationConveyance {
  private AttestationConveyance() {}

  /**
   * Apply the attestation conveyance preference to an attestation object, as required of the client
   * by WebAuthn. Unless a direct, indirect or enterprise attestation was requested, the attestation
   * statement is replaced by the "none" format. The credential data, including the AAGUID, is
   * preserved. Self attestation is left as it is.
   *
   * @param attestationObject the attestation object as returned by the authenticator
   * @param preference the requested attestation conveyance preference
   * @return the attestation object to return to the caller
   */
  static AttestationObject apply(AttestationObject attestationObject, @Nullable String preference) {
    if (AttestationConveyancePreference.DIRECT.equals(preference)
        || AttestationConveyancePreference.INDIRECT.equals(preference)
        || AttestationConveyancePreference.ENTERPRISE.equals(preference)
        || "none".equals(attestationObject.getFormat())
        || isSelfAttestation(attestationObject)) {
      return attestationObject;
    }
    return new AttestationObject(
        "none",
        attestationObject.getAuthenticatorData(),
        Collections.emptyMap(),
        attestationObject.getEnterpriseAttestation(),
        attestationObject.getLargeBlobKey(),
        attestationObject.getUnsignedExtensionOutputs());
  }

  /**
   * Whether the authenticator used self attestation, which WebAuthn (Create a New Credential,
   * "none") says needs no further action: the "packed" format, no certificate chain and an AAGUID
   * of 16 zero bytes. Such a statement is signed by the credential's own key, so it identifies
   * nothing beyond the credential, and keeping it lets the Relying Party verify it.
   */
  private static boolean isSelfAttestation(AttestationObject attestationObject) {
    AttestedCredentialData credentialData =
        attestationObject.getAuthenticatorData().getAttestedCredentialData();
    if (credentialData == null) {
      return false;
    }
    for (byte b : credentialData.getAaguid()) {
      if (b != 0) {
        return false;
      }
    }
    return "packed".equals(attestationObject.getFormat())
        && !attestationObject.getAttestationStatement().containsKey("x5c");
  }
}

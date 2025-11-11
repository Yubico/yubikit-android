/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.fido.client.clientdata;

import java.util.Map;
import javax.annotation.Nullable;

/** Provides access to clientDataJSON (raw) or only its SHA-256 hash. */
public interface ClientDataProvider {
  /**
   * Get SHA-256 hash of client data
   *
   * @return hash of client data
   */
  byte[] getHash();

  /**
   * Get clientDataJSON bytes, if available
   *
   * @return client data bytes
   */
  byte[] getClientDataJson();

  /**
   * Returns true if this instance contains raw version of the client data.
   *
   * @return true if client data JSON is present
   */
  boolean hasClientDataJson();

  /**
   * Create instance from provided JSON byte array.
   *
   * @param clientDataJson ClientDataJSON byte array
   * @return new ClientDataProvider object constructed from provided raw data
   */
  static ClientDataProvider fromClientDataJson(byte[] clientDataJson) {
    return new JsonClientData(clientDataJson);
  }

  /**
   * Create instance from existing hash. The raw data is unavailable.
   *
   * @param hash SHA-256 hash of ClientDataJSON
   * @return new ClientDataProvider instance constructed with provided hash
   */
  static ClientDataProvider fromHash(byte[] hash) {
    return new HashedClientData(hash);
  }

  /**
   * Builds valid JSON from the provided parameters.
   *
   * @param type WebAuthn operation type as a {@link ClientDataType}. Use predefined constants
   *     ({@code ClientDataType.CREATE}, {@code ClientDataType.GET}).
   *     <p>Use a custom value via {@link ClientDataType#of(String)} for future extensions.
   * @param challenge Raw challenge bytes; will be base64url-encoded internally.
   * @param origin This member contains the fully qualified origin of the requester, as provided to
   *     the authenticator by the client, in the syntax defined by [RFC6454].
   * @param crossOrigin This is an OPTIONAL member.
   * @param topOrigin This OPTIONAL member contains the fully qualified top-level origin of the
   *     requester, in the syntax defined by [RFC6454]. It is set only if the call was made from
   *     context that is not same-origin with its ancestors, i.e. if crossOrigin is true. Supplying
   *     topOrigin causes crossOrigin to be forced true.
   * @param extraParameters Additional client data members. Values of type byte[] are automatically
   *     base64url-encoded as strings.
   * @return JSON data
   * @see <a href="https://www.w3.org/TR/webauthn-3/#dictionary-client-data">Client data</a>
   * @see <a href="https://www.w3.org/TR/webauthn-3/#clientdatajson-serialization">ClientData
   *     Serialization</a>
   */
  static ClientDataProvider fromFields(
      ClientDataType type,
      byte[] challenge,
      String origin,
      boolean crossOrigin,
      @Nullable String topOrigin,
      @Nullable Map<String, ?> extraParameters) {
    return JsonClientData.createFromFields(
        type, challenge, origin, crossOrigin, topOrigin, extraParameters);
  }
}

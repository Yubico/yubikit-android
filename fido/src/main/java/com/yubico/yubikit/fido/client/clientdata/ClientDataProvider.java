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

/**
 * Provides access to WebAuthn {@code clientDataJSON} (raw bytes) or only its SHA-256 hash.
 *
 * <p>If a {@code ClientDataProvider} is constructed with only the hash, {@link
 * #getClientDataJson()} returns an empty array and {@link #hasClientDataJson()} returns false.
 */
public interface ClientDataProvider {
  /**
   * Returns the SHA-256 hash (32 bytes) of {@code clientDataJSON}.
   *
   * @return SHA-256 hash of {@code clientDataJSON}
   */
  byte[] getHash();

  /**
   * Returns the raw {@code clientDataJSON} bytes, if available. If only the hash is provided,
   * returns an empty array.
   *
   * @return raw {@code clientDataJSON} bytes, or empty array if unavailable
   */
  byte[] getClientDataJson();

  /**
   * Indicates whether raw {@code clientDataJSON} bytes are present.
   *
   * @return true if raw {@code clientDataJSON} is present, false otherwise
   */
  boolean hasClientDataJson();

  /**
   * Creates a {@code ClientDataProvider} from the provided {@code clientDataJSON} byte array.
   *
   * @param clientDataJson raw {@code clientDataJSON} byte array
   * @return new {@code ClientDataProvider} instance
   */
  static ClientDataProvider fromClientDataJson(byte[] clientDataJson) {
    return new JsonClientData(clientDataJson);
  }

  /**
   * Creates a {@code ClientDataProvider} from an existing SHA-256 hash. The raw {@code
   * clientDataJSON} bytes are not available.
   *
   * @param hash SHA-256 hash (32 bytes) of {@code clientDataJSON}
   * @return new {@code ClientDataProvider} instance
   */
  static ClientDataProvider fromHash(byte[] hash) {
    return new HashedClientData(hash);
  }
}

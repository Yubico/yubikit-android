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
 * Internal immutable representation of the WebAuthn {@code clientDataJSON} hash (SHA-256 over the
 * original JSON). Used when only the hash is required and the raw {@code clientDataJSON} bytes are
 * neither needed nor retained.
 *
 * <ul>
 *   <li>Accepts and stores exactly 32 bytes (SHA-256); constructor enforces length.
 *   <li>Does <b>not</b> retain or reconstruct the raw JSON; {@link #getClientDataJson()} returns an
 *       empty array.
 * </ul>
 *
 * <p>Package-private: external callers interact via {@link ClientDataProvider}.
 *
 * @see JsonClientData
 * @see ClientDataProvider
 */
final class HashedClientData implements ClientDataProvider {
  private static final int SHA256_LEN = 32;
  private static final byte[] EMPTY = new byte[0];
  private final byte[] hash;

  HashedClientData(byte[] hash) {
    if (hash.length != SHA256_LEN) {
      throw new IllegalArgumentException(
          "clientDataHash must be " + SHA256_LEN + " bytes (SHA-256).");
    }
    this.hash = hash.clone();
  }

  @Override
  public byte[] getHash() {
    return hash.clone();
  }

  @Override
  public byte[] getClientDataJson() {
    return EMPTY;
  }

  @Override
  public boolean hasClientDataJson() {
    return false;
  }
}

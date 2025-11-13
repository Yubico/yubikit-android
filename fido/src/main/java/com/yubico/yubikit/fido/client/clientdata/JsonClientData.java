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

import com.yubico.yubikit.fido.client.Utils;

/**
 * Internal immutable representation of WebAuthn {@code clientDataJSON}.
 *
 * <p>Provides both the raw JSON bytes and their SHA-256 hash.
 *
 * <p>This class is package-private; external users interact via {@link ClientDataProvider}
 * factories.
 *
 * @see ClientDataProvider
 */
final class JsonClientData implements ClientDataProvider {
  private final byte[] raw;
  private final byte[] hash;

  JsonClientData(byte[] raw) {
    this.raw = raw.clone();
    this.hash = Utils.hash(this.raw);
  }

  @Override
  public byte[] getHash() {
    return hash.clone();
  }

  @Override
  public byte[] getClientDataJson() {
    return raw.clone();
  }

  @Override
  public boolean hasClientDataJson() {
    return true;
  }
}

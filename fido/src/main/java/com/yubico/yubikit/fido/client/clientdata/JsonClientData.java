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
 * <p>Provides both the raw JSON bytes and their SHA-256 hash. Used when full {@code clientDataJSON}
 * must be supplied (e.g. for attestation) rather than only its hash.
 *
 * <p>Construction either wraps provided raw bytes or builds deterministic JSON from field inputs:
 *
 * <ul>
 *   <li>Standard fields: type, challenge (base64url), origin, crossOrigin, optional topOrigin.
 *   <li>Extra parameters: filtered to exclude reserved keys and serialized in lexicographic key
 *       order at the top level.
 *   <li>Nested structures: values of type {@code Map} and {@code Iterable} (e.g. {@code List},
 *       {@code Set}) are recursively serialized into JSON (not via {@code toString()}).
 *   <li>Nested {@code Map} keys are emitted in the iteration order of the provided map (not
 *       re-sorted). Use {@code LinkedHashMap} if deterministic ordering is required.
 *   <li>Reserved key filtering applies only to the top-level extras; nested maps are not filtered.
 *   <li>Binary ({@code byte[]}) values at any depth are base64url encoded as JSON strings.
 *   <li>Other object types (non-primitive, non-collection, non-byte[]) are serialized via {@code
 *       String.valueOf(value)} as JSON strings.
 * </ul>
 *
 * <p>Reserved keys ignored in top-level extras: {@code type}, {@code challenge}, {@code origin},
 * {@code crossOrigin}, {@code topOrigin}.
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

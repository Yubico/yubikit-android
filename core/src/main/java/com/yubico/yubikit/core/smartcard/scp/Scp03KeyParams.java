/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.core.smartcard.scp;

/**
 * SCP key parameters for performing an SCP03 authentication. SCP03 uses a set of three keys, each
 * with their own KID, but a shared KVN.
 */
public class Scp03KeyParams implements ScpKeyParams {
  private final KeyRef keyRef;
  final StaticKeys keys;

  /**
   * @param keyRef the reference to the key set to authenticate with.
   * @param keys the key material for authentication.
   */
  public Scp03KeyParams(KeyRef keyRef, StaticKeys keys) {
    if ((0xff & keyRef.getKid()) > 3) {
      throw new IllegalArgumentException("Invalid KID for SCP03");
    }
    this.keyRef = keyRef;
    this.keys = keys;
  }

  @Override
  public KeyRef getKeyRef() {
    return keyRef;
  }
}

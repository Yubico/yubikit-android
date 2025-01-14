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

package com.yubico.yubikit.fido.ctap;

import com.yubico.yubikit.core.util.Pair;
import java.util.Map;

/**
 * Implements a dummy PIN/UV Auth Protocol
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authnrClientPin-puaprot-abstract-dfn">PIN/UV
 *     Auth Protocol Abstract Definition</a>.
 */
public class PinUvAuthDummyProtocol implements PinUvAuthProtocol {
  @Override
  public int getVersion() {
    throw new UnsupportedPinUvAuthProtocolError();
  }

  @Override
  public Pair<Map<Integer, ?>, byte[]> encapsulate(Map<Integer, ?> peerCoseKey) {
    throw new UnsupportedPinUvAuthProtocolError();
  }

  @Override
  public byte[] encrypt(byte[] key, byte[] demPlaintext) {
    throw new UnsupportedPinUvAuthProtocolError();
  }

  @Override
  public byte[] decrypt(byte[] key, byte[] demCiphertext) {
    throw new UnsupportedPinUvAuthProtocolError();
  }

  @Override
  public byte[] authenticate(byte[] key, byte[] message) {
    throw new UnsupportedPinUvAuthProtocolError();
  }

  @Override
  public byte[] kdf(byte[] z) {
    throw new UnsupportedPinUvAuthProtocolError();
  }
}

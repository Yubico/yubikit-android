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
 * A PIN/UV auth protocol (aka pinUvAuthProtocol) ensures that PINs are encrypted when sent to an
 * authenticator and are exchanged for a pinUvAuthToken that serves to authenticate subsequent
 * commands.
 */
public interface PinUvAuthProtocol {
  /**
   * Returns the version number of the PIN/UV Auth protocol.
   *
   * @return the version of the protocol
   */
  int getVersion();

  /**
   * Generates an encapsulation for the authenticator’s public key and returns the message to
   * transmit and the shared secret.
   *
   * @param peerCoseKey a public key returned by the YubiKey
   * @return a Pair containing a keyAgreement to transmit, and the shared secret.
   */
  Pair<Map<Integer, ?>, byte[]> encapsulate(Map<Integer, ?> peerCoseKey);

  /** Computes shared secret */
  byte[] kdf(byte[] z);

  /**
   * Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext. The
   * plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
   *
   * @param key the secret key to use
   * @param demPlaintext the value to encrypt
   * @return the encrypted value
   */
  byte[] encrypt(byte[] key, byte[] demPlaintext);

  /**
   * Decrypts a ciphertext and returns the plaintext.
   *
   * @param key the secret key to use
   * @param demCiphertext the value to decrypt
   * @return the decrypted value
   */
  byte[] decrypt(byte[] key, byte[] demCiphertext);

  /**
   * Computes a MAC of the given message.
   *
   * @param key the secret key to use
   * @param message the message to sign
   * @return a signature
   */
  byte[] authenticate(byte[] key, byte[] message);
}

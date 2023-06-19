/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.ctap;

import android.util.Pair;

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
     * Generates an encapsulation for the authenticator’s public key and returns the message to transmit and the shared secret.
     *
     * @param peerCoseKey a public key returned by the YubiKey
     * @return a Pair containing a keyAgreement to transmit, and the shared secret.
     */
    Pair<Map<Integer, ?>, byte[]> encapsulate(Map<Integer, ?> peerCoseKey);

    /**
     * Encrypts a plaintext to produce a ciphertext, which may be longer than the plaintext. The plaintext is restricted to being a multiple of the AES block size (16 bytes) in length.
     *
     * @param key          the secret key to use
     * @param demPlaintext the value to encrypt
     * @return the encrypted value
     */
    byte[] encrypt(byte[] key, byte[] demPlaintext);

    /**
     * Decrypts a ciphertext and returns the plaintext.
     *
     * @param key           the secret key to use
     * @param demCiphertext the value to decrypt
     * @return the decrypted value
     */
    byte[] decrypt(byte[] key, byte[] demCiphertext);

    /**
     * Computes a MAC of the given message.
     *
     * @param key     the secret key to use
     * @param message the message to sign
     * @return a signature
     */
    byte[] authenticate(byte[] key, byte[] message);
}

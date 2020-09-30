/*
 * Copyright (C) 2020 Yubico.
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
package com.yubico.yubikit.piv;

import java.security.PublicKey;

/**
 * Metadata about a key in a slot.
 */
public class SlotMetadata {
    private final KeyType keyType;
    private final PinPolicy pinPolicy;
    private final TouchPolicy touchPolicy;
    private final boolean generated;
    private final byte[] publicKeyEncoded;

    SlotMetadata(KeyType keyType, PinPolicy pinPolicy, TouchPolicy touchPolicy, boolean generated, byte[] publicKeyEncoded) {
        this.keyType = keyType;
        this.pinPolicy = pinPolicy;
        this.touchPolicy = touchPolicy;
        this.generated = generated;
        this.publicKeyEncoded = publicKeyEncoded;
    }

    /**
     * The type of the key stored in a slot.
     *
     * @return the key type
     */
    public KeyType getKeyType() {
        return keyType;
    }

    /**
     * The PIN policy for using the key.
     *
     * @return the PIN policy
     */
    public PinPolicy getPinPolicy() {
        return pinPolicy;
    }

    /**
     * The touch policy for using the key.
     *
     * @return the touch policy
     */
    public TouchPolicy getTouchPolicy() {
        return touchPolicy;
    }

    /**
     * Whether the key was generated on the YubiKey or imported. A generated key can be attested,
     * and exists only in a single YubiKey.
     *
     * @return true if the key was generated on the YubiKey
     */
    public boolean isGenerated() {
        return generated;
    }

    /**
     * Gets the public key corresponding to the key in the slot.
     *
     * @return the slots public key
     */
    public PublicKey getPublicKey() {
        return PivSession.parsePublicKeyFromDevice(keyType, publicKeyEncoded);
    }
}

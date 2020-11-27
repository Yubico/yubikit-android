/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.oath;

/**
 * Allows the implementation of custom backends to unlock an OathSession.
 * <p>
 * The AccessKey gives the OathSession the ability to unlock a session without providing the actual
 * key material, which allows it to be stored in the Android KeyStore or similar.
 */
public interface AccessKey {
    /**
     * Create a HMAC-SHA1 signature over the given challenge, using an OATH Access Key.
     *
     * @param challenge a challenge to sign
     * @return a signature over the given challenge
     */
    byte[] calculateResponse(byte[] challenge);
}
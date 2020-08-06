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

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * Interface that needs to be implemented to provide custom signing with stored secret
 */
public interface ChallengeSigner {

    /**
     * The response computed by performing the correct HMAC function of provided challenge with the correct key.
     * @param challenge the challenge that needs to be signed
     * @return HMAC of the challenge
     * @throws InvalidKeyException in case of crypto operation error
     * @throws NoSuchAlgorithmException in case of crypto operation error
     */
    byte[] sign(byte[] challenge) throws InvalidKeyException, NoSuchAlgorithmException;
}
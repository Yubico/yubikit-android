/*
 * Copyright (C) 2023 Yubico.
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

package com.yubico.yubikit.core.internal.codec;

import java.util.Base64;

/**
 * Default implementation of Base64Codec
 * <p>
 * Only for internal use.
 */
public class DefaultBase64Codec implements Base64Codec {

    @Override
    public String toUrlSafeString(byte[] data) {
        return new String(Base64.getUrlEncoder().withoutPadding().encode(data));
    }

    public String toString(byte[] data) {
        return new String(Base64.getEncoder().withoutPadding().encode(data));
    }

    @Override
    public byte[] fromUrlSafeString(String data) {
        return Base64.getUrlDecoder().decode(data);
    }

    public byte[] fromString(String data) {
        return Base64.getDecoder().decode(data);
    }
}
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

import java.util.Iterator;
import java.util.ServiceLoader;

/**
 * Loads and provides Base64 implementation
 * <p>
 * Only for internal use.
 */
public class Base64 {

    private static final Base64Codec base64Codec;

    static {
        ServiceLoader<Base64Codec> codecLoader = ServiceLoader.load(Base64Codec.class);
        final Iterator<Base64Codec> iterator = codecLoader.iterator();
        base64Codec = iterator.hasNext() ? iterator.next() : new DefaultBase64Codec();
    }

    /**
     * Encodes binary data to Base64 URL safe format.
     * <p>
     * Internal use only.
     * @param data date to encode
     * @return Encoded data in Base64 URL safe format
     */
    public static String encode(byte[] data) {
        return base64Codec.toUrlSafeString(data);
    }

    /**
     * Decodes Base64 URL safe formatted string to binary data.
     * <p>
     * Internal use only.
     * @param data data to decode in Base64 URL safe format
     * @return decoded data
     */
    public static byte[] decode(String data) {
        return base64Codec.fromUrlSafeString(data);
    }

    /**
     * Returns Base64Codec
     * <p>
     * Internal use only.
     */
    public static Base64Codec getBase64Codec() {
        return base64Codec;
    }
}

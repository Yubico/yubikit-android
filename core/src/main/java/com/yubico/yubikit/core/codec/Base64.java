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

package com.yubico.yubikit.core.codec;

import java.util.ServiceLoader;

public class Base64 {

    private static final Base64Codec base64Codec;

    static {
        ServiceLoader<Base64Codec> serviceLoader = ServiceLoader.load(Base64Codec.class);
        base64Codec = serviceLoader.iterator().next();
    }

    public static String encode(byte[] data) {
        return base64Codec.encode(data);
    }

    public static byte[] decode(String data) {
        return base64Codec.decode(data);
    }

}

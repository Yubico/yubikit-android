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

/**
 * Helper for performing Base64 data conversions.
 * <p>
 * Only for internal use.
 */
public interface Base64Codec {
    /**
     * @param data binary data
     * @return String with no wrapped base64 data without padding
     */
    String toString(byte[] data);

    /**
     * @param data String with no wrapped base64 content
     * @return decoded binary data
     */
    byte[] fromString(String data);

    /**
     * @param data binary data
     * @return String with no wrapped base64 data without padding, with only safe characters as defined
     * in RFC 4648
     */
    String toUrlSafeString(byte[] data);

    /**
     * @param data String with no wrapped base64 data without padding, with only safe characters as defined
     * in RFC 4648
     * @return decoded binary data
     */
    byte[] fromUrlSafeString(String data);
}

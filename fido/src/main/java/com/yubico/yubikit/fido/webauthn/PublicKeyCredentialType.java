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

package com.yubico.yubikit.fido.webauthn;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public enum PublicKeyCredentialType {
    PUBLIC_KEY;

    private final static Set<String> validValues;

    @Override
    public String toString() {
        return name().replace("_", "-").toLowerCase();
    }

    /**
     * Verify that a string value represents valid credential type
     *
     * @param type name of a credential type
     * @return true if {@code type} is a valid {@code PublicKeyCredentialType}
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enumdef-publickeycredentialtype">Credential Type Enumeration</a>
     */
    @SuppressWarnings("unused")
    public static boolean contains(String type) {
        return validValues.contains(type);
    }

    static {
        Set<String> set = new HashSet<>();
        for (PublicKeyCredentialType publicKeyCredentialType : PublicKeyCredentialType.values()) {
            set.add(publicKeyCredentialType.toString());
        }
        validValues = Collections.unmodifiableSet(set);
    }
}

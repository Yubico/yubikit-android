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

import javax.annotation.Nullable;

public enum AttestationConveyancePreference {
    NONE, INDIRECT, DIRECT, ENTERPRISE;

    @Override
    public String toString() {
        return name().toLowerCase();
    }

    @Nullable
    public static AttestationConveyancePreference fromString(@Nullable String value) {
        if(value == null) {
            return null;
        }
        try {
            return AttestationConveyancePreference.valueOf(value.toUpperCase());
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}

/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.fido.client.extensions;

import com.yubico.yubikit.fido.webauthn.Extensions;

import javax.annotation.Nullable;

public class CredProtectExtension extends Extension {

    static final String OPTIONAL = "userVerificationOptional";
    static final String OPTIONAL_WITH_LIST = "userVerificationOptionalWithCredentialIDList";
    static final String REQUIRED = "userVerificationRequired";

    public CredProtectExtension() {
        super("credProtect");
    }

    @Override
    ProcessingResult processInput(CreateInputArguments arguments) {

        Extensions extensions = arguments.creationOptions.getExtensions();

        String credentialProtectionPolicy = (String) extensions.get("credentialProtectionPolicy");
        if (credentialProtectionPolicy == null) {
            return null;
        }

        @Nullable Integer credProtect = null;
        switch (credentialProtectionPolicy) {
            case OPTIONAL:
                credProtect = 0x01;
                break;
            case OPTIONAL_WITH_LIST:
                credProtect = 0x02;
                break;
            case REQUIRED:
                credProtect = 0x03;
                break;
        }
        Boolean enforce = (Boolean) extensions.get("enforceCredentialProtectionPolicy");
        if (Boolean.TRUE.equals(enforce) &&
                !isSupported(arguments.ctap) &&
                credProtect != null &&
                credProtect > 0x01) {
            throw new IllegalArgumentException("Authenticator does not support Credential Protection");
        }

        return credProtect != null
                ? resultWithData(name, credProtect)
                : null;
    }
}

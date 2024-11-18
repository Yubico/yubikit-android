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

import java.util.Collections;

import javax.annotation.Nullable;

public class CredProtectExtension extends Extension {

    static final String OPTIONAL = "userVerificationOptional";
    static final String OPTIONAL_WITH_LIST = "userVerificationOptionalWithCredentialIDList";
    static final String REQUIRED = "userVerificationRequired";

    public CredProtectExtension() {
        super("credProtect");
    }

    @Override
    MakeCredentialProcessingResult makeCredential(CreateInputArguments arguments) {

        Extensions extensions = arguments.getCreationOptions().getExtensions();

        String credentialProtectionPolicy = (String) extensions.get("credentialProtectionPolicy");
        if (credentialProtectionPolicy == null) {
            return null;
        }

        Integer credProtect = credProtectValue(credentialProtectionPolicy);
        Boolean enforce = (Boolean) extensions.get("enforceCredentialProtectionPolicy");
        if (Boolean.TRUE.equals(enforce) &&
                !isSupported(arguments.getCtap()) &&
                credProtect != null &&
                credProtect > 0x01) {
            throw new IllegalArgumentException("Authenticator does not support Credential Protection");
        }
        return credProtect != null
                ? new MakeCredentialProcessingResult(() ->
                Collections.singletonMap(name, credProtect))
                : null;
    }

    @Nullable
    private Integer credProtectValue(String optionsValue) {
        switch(optionsValue) {
            case OPTIONAL:
                return 0x01;
            case OPTIONAL_WITH_LIST:
                return 0x02;
            case REQUIRED:
                return 0x03;
            default:
                return null;
        }
    }
}

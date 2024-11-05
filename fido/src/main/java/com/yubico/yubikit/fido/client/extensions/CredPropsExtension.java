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

import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;

import java.util.Collections;

import javax.annotation.Nullable;

public class CredPropsExtension extends Extension {

    public CredPropsExtension() {
        super("credProps");
    }

    @Nullable
    Boolean rk = null;

    @Override
    ProcessingResult processInput(CreateInputArguments arguments) {

        PublicKeyCredentialCreationOptions options = arguments.getCreationOptions();
        Extensions extensions = options.getExtensions();

        if (extensions.has(name)) {
            AuthenticatorSelectionCriteria authenticatorSelection = options.getAuthenticatorSelection();
            rk = authenticatorSelection != null &&
                    ResidentKeyRequirement.REQUIRED.equals(authenticatorSelection.getResidentKey());

            return resultWithoutData();
        }
        return null;
    }

    @Override
    ProcessingResult processOutput(AttestationObject ignoredAttestationObject) {
        if (rk != null) {
            return resultWithData(name, Collections.singletonMap("rk", rk));
        }
        return null;
    }
}

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

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;

import java.util.Collections;
import java.util.Map;

import javax.annotation.Nullable;

class CredPropsExtension extends Extension {
    CredPropsExtension(final Ctap2Session ctap) {
        super("credProps", ctap);
    }

    @Nullable
    Boolean rk = null;

    @Override
    boolean processInput(CreateInputArguments arguments) {

        PublicKeyCredentialCreationOptions options = arguments.creationOptions;
        Extensions extensions = options.getExtensions();

        if (extensions.has(name)) {
            AuthenticatorSelectionCriteria authenticatorSelection = options.getAuthenticatorSelection();
            rk = authenticatorSelection != null &&
                    ResidentKeyRequirement.REQUIRED.equals(authenticatorSelection.getResidentKey());

            return true;
        }
        return false;
    }

    @Override
    Map<String, Object> processOutput(AttestationObject ignoredAttestationObject) {
        if (rk != null) {
            return Collections.singletonMap(name,
                    Collections.singletonMap("rk", rk));
        }
        return null;
    }
}

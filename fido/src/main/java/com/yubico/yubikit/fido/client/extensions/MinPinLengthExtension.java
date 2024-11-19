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
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;

import java.util.Collections;

import javax.annotation.Nullable;

public class MinPinLengthExtension extends Extension {

    public MinPinLengthExtension() {
        super("minPinLength");
    }

    @Override
    protected boolean isSupported(Ctap2Session ctap) {
        return super.isSupported(ctap) && ctap.getCachedInfo().getOptions()
                .containsKey("setMinPINLength");
    }

    @Nullable
    @Override
    public RegistrationProcessor makeCredential(
            Ctap2Session ctap,
            PublicKeyCredentialCreationOptions options,
            PinUvAuthProtocol pinUvAuthProtocol) {

        if (!isSupported(ctap)) {
            return null;
        }
        Boolean input = (Boolean) options.getExtensions().get(name);
        if (input == null) {
            return null;
        }
        return new RegistrationProcessor(
                pinToken -> Collections.singletonMap(name, Boolean.TRUE.equals(input)));
    }
}

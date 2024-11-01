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
import com.yubico.yubikit.fido.webauthn.Extensions;

class MinPinLengthExtension extends Extension {
    MinPinLengthExtension(final Ctap2Session ctap) {
        super("minPinLength", ctap);
    }

    @Override
    boolean isSupported() {
        return super.isSupported() && ctap.getCachedInfo().getOptions()
                .containsKey("setMinPINLength");
    }

    @Override
    ExtensionInput processInput(ExtensionCreateInput parameters) {

        Extensions extensions = parameters.creationOptions.getExtensions();
        if (!isSupported()) {
            return ExtensionInput.unused();
        }
        Boolean input = (Boolean) extensions.get(name);
        if (input == null) {
            return ExtensionInput.unused();
        }
        return extensionInput(Boolean.TRUE.equals(input));
    }
}

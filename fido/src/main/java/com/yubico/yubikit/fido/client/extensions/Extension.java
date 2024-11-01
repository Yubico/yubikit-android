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

import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AttestationObject;

import javax.annotation.Nullable;

public class Extension {
    protected final String name;
    protected final Ctap2Session ctap;

    protected Extension(String name, final Ctap2Session ctap) {
        this.name = name;
        this.ctap = ctap;
    }

    boolean isSupported() {
        return ctap.getCachedInfo().getExtensions().contains(name);
    }

    ExtensionInput extensionInput(Object data) {
        return extensionInput(data, ClientPin.PIN_PERMISSION_NONE);
    }

    ExtensionInput extensionInput(Object data, int permissions) {
        return ExtensionInput.withAuthenticatorInput(name, data, permissions);
    }

    ExtensionInput processInput(
            ExtensionCreateInput ignoredCreateInputParameters) {
        return ExtensionInput.unused();
    }

    @Nullable
    ClientExtensionResult processCreateOutput(AttestationObject ignoredAttestationObject) {
        return null;
    }

    @Nullable
    ClientExtensionResult processCreateOutput(
            AttestationObject attestationObject,
            ExtensionCreateOutput ignoredParameters) {
        return processCreateOutput(attestationObject);
    }

    ExtensionInput processInput(ExtensionGetInput ignoredParameters) {
        return ExtensionInput.unused();
    }

    @Nullable
    ClientExtensionResult processGetOutput(Ctap2Session.AssertionData ignoredAssertionData) {
        return null;
    }

    @Nullable
    ClientExtensionResult processGetOutput(
            Ctap2Session.AssertionData assertionData,
            ExtensionGetOutput ignoredParameters) {
        return processGetOutput(assertionData);
    }
}

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

import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;

import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

// Client Extension processing
public class Extensions {

    final List<Extension> usedExtensions = new ArrayList<>();
    final List<String> supportedExtensions = Arrays.asList(
            "hmac-secret",
            "largeBlobKey",
            "credBlob",
            "credProps",
            "credProtect",
            "minPinLength"
    );
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Extensions.class);

    final Map<String, Object> authenticatorInput = new HashMap<>();
    int permissions = ClientPin.PIN_PERMISSION_NONE;

    public static Extensions processExtensions(Ctap2Session ctap, Extension.CreateInputArguments arguments) {
        return new Extensions(ctap, e -> e.processInput(arguments));
    }

    public static Extensions processExtensions(Ctap2Session ctap, Extension.GetInputArguments arguments) {
        return new Extensions(ctap, e -> e.processInput(arguments));
    }

    private Extensions(Ctap2Session ctap, InputArgumentsProcessor processor) {
        for (String extensionName : supportedExtensions) {
            Extension extension = getByName(extensionName, ctap);
            if (extension == null) {
                Logger.debug(logger, "Extension {} not supported", extensionName);
                continue;
            }

            if (processor.process(extension)) {
                usedExtensions.add(extension);
                if (extension.getAuthenticatorInput() != null) {
                    permissions |= extension.getPermissions();
                    authenticatorInput.putAll(extension.getAuthenticatorInput());
                }
            }
        }
    }

    public Map<String, Object> getAuthenticatorInput() {
        return authenticatorInput;
    }

    public int getRequiredPermissions() {
        return permissions;
    }

    public ClientExtensionResults getClientExtensionResults(
            Ctap2Session.AssertionData assertionData,
            Extension.GetOutputArguments arguments) {
        return getClientExtensionResults(e -> e.processOutput(assertionData, arguments));
    }

    public ClientExtensionResults getClientExtensionResults(
            AttestationObject attestationObject,
            Extension.CreateOutputArguments arguments) {
        return getClientExtensionResults(e -> e.processOutput(attestationObject, arguments));
    }

    private ClientExtensionResults getClientExtensionResults(OutputArgumentsProcessor processor) {
        ClientExtensionResults extensionExtensionResults = new ClientExtensionResults();

        for (Extension extension : usedExtensions) {
            Map<String, Object> extensionResult = processor.process(extension);
            if (extensionResult != null) {
                extensionExtensionResults.add(extensionResult);
            }
        }

        return extensionExtensionResults;
    }

    interface InputArgumentsProcessor {
        boolean process(Extension extension);
    }

    interface OutputArgumentsProcessor {
        @Nullable
        Map<String, Object> process(Extension extension);
    }

    @Nullable
    static private Extension getByName(String name, final Ctap2Session ctap) {
        switch (name) {
            case "hmac-secret":
                return new HmacSecretExtension(ctap);
            case "largeBlobKey":
                return new LargeBlobExtension(ctap);
            case "credBlob":
                return new CredBlobExtension(ctap);
            case "credProps":
                return new CredPropsExtension(ctap);
            case "credProtect":
                return new CredProtectExtension(ctap);
            case "minPinLength":
                return new MinPinLengthExtension(ctap);
        }
        return null;
    }
}

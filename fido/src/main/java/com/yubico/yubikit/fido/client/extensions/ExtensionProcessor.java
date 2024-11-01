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
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AttestationObject;

import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

// Client Extension processing
public class ExtensionProcessor {

    final List<Extension> usedExtensions = new ArrayList<>();
    final List<String> supportedExtensions = Arrays.asList(
            "hmac-secret",
            "largeBlobKey",
            "credBlob",
            "credProps",
            "credProtect",
            "minPinLength"
    );

    final Map<String, Object> authenticatorInput = new HashMap<>();

    int permissions = 0;

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(ExtensionProcessor.class);

    public ExtensionProcessor(Ctap2Session ctap, ExtensionCreateInput parameters) {
        for (String extensionName : supportedExtensions) {
            Extension extension = getByName(extensionName, ctap);
            if (extension == null) {
                Logger.debug(logger, "Extension {} not supported", extensionName);
                continue;
            }

            ExtensionInput result = extension.processInput(parameters);

            if (result.isUsed()) {
                usedExtensions.add(extension);
                if (result.getAuthenticatorInput() != null) {
                    permissions |= result.getRequiredPermissions();
                    authenticatorInput.putAll(result.getAuthenticatorInput());
                }
            }
        }
    }

    public ExtensionProcessor(Ctap2Session ctap, ExtensionGetInput parameters) {
        for (String extensionName : supportedExtensions) {
            Extension extension = getByName(extensionName, ctap);
            if (extension == null) {
                Logger.debug(logger, "Extension {} not supported", extensionName);
                continue;
            }

            ExtensionInput input = extension.processInput(parameters);
            if (input.isUsed()) {
                usedExtensions.add(extension);
                if (input.getAuthenticatorInput() != null) {
                    permissions |= input.getRequiredPermissions();
                    authenticatorInput.putAll(input.getAuthenticatorInput());
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
            AttestationObject attestationObject,
            ExtensionCreateOutput parameters) {
        ClientExtensionResults extensionExtensionResults = new ClientExtensionResults();

        for (Extension extension : usedExtensions) {
            ClientExtensionResult extensionResult = extension.processCreateOutput(
                    attestationObject,
                    parameters
            );
            if (extensionResult != null) {
                extensionExtensionResults.add(extensionResult);
            }
        }

        return extensionExtensionResults;
    }

    public ClientExtensionResults getClientExtensionResults(
            Ctap2Session.AssertionData assertionData,
            ExtensionGetOutput parameters) {
        ClientExtensionResults extensionExtensionResults = new ClientExtensionResults();

        for (Extension extension : usedExtensions) {
            ClientExtensionResult extensionResult = extension.processGetOutput(
                    assertionData, parameters

            );
            if (extensionResult != null) {
                extensionExtensionResults.add(extensionResult);
            }
        }

        return extensionExtensionResults;
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

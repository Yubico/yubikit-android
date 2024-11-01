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

package com.yubico.yubikit.fido.client;

import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.Extension;

import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

// Client Extension processing
class Extensions {

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

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Extensions.class);

    Extensions(Ctap2Session ctap,
               Extension.CreateInputParameters parameters) {
        for (String extensionName : supportedExtensions) {
            Extension extension = Extension.Builder.get(extensionName, ctap);
            if (extension == null) {
                Logger.debug(logger, "Extension {} not supported", extensionName);
                continue;
            }

            Extension.ExtensionInput result = extension.processInput(parameters);

            if (result.isUsed()) {
                usedExtensions.add(extension);
                if (result.getAuthenticatorInput() != null) {
                    permissions |= result.getRequiredPermissions();
                    authenticatorInput.putAll(result.getAuthenticatorInput());
                }
            }
        }
    }

    Extensions(Ctap2Session ctap, Extension.GetInputParameters parameters) {
        for (String extensionName : supportedExtensions) {
            Extension extension = Extension.Builder.get(extensionName, ctap);
            if (extension == null) {
                Logger.debug(logger, "Extension {} not supported", extensionName);
                continue;
            }

            Extension.ExtensionInput input = extension.processInput(parameters);
            if (input.isUsed()) {
                usedExtensions.add(extension);
                if (input.getAuthenticatorInput() != null) {
                    permissions |= input.getRequiredPermissions();
                    authenticatorInput.putAll(input.getAuthenticatorInput());
                }
            }
        }
    }

    Map<String, Object> getAuthenticatorInput() {
        return authenticatorInput;
    }

    int getRequiredPermissions() {
        return permissions;
    }

    Extension.ExtensionResults getClientExtensionResults(AttestationObject attestationObject, Extension.CreateOutputParameters parameters) {
        Extension.ExtensionResults extensionExtensionResults = new Extension.ExtensionResults();

        for (Extension extension : usedExtensions) {
            Extension.ExtensionResult extensionResult = extension.processCreateOutput(
                    attestationObject,
                    parameters
            );
            if (extensionResult != null) {
                extensionExtensionResults.add(extensionResult);
            }
        }

        return extensionExtensionResults;
    }

    Extension.ExtensionResults getClientExtensionResults(Ctap2Session.AssertionData assertionData, Extension.GetOutputParameters parameters) {
        Extension.ExtensionResults extensionExtensionResults = new Extension.ExtensionResults();

        for (Extension extension : usedExtensions) {
            Extension.ExtensionResult extensionResult = extension.processGetOutput(
                    assertionData, parameters

            );
            if (extensionResult != null) {
                extensionExtensionResults.add(extensionResult);
            }
        }

        return extensionExtensionResults;
    }
}

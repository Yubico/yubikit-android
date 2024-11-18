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
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;

import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ServiceLoader;

// Client Extension processing
public class Extensions {
    final List<Extension.MakeCredentialContinuation> mcContinuations = new ArrayList<>();
    final List<Extension.GetAssertionContinuation> gaContinuations = new ArrayList<>();
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Extensions.class);

    final Map<String, Object> authenticatorInput = new HashMap<>();
    int permissions = ClientPin.PIN_PERMISSION_NONE;

    public static Extensions processExtensions(Extension.CreateInputArguments arguments) {
        return new Extensions(arguments);
    }

    public static Extensions processExtensions(Extension.GetInputArguments arguments) {
        return new Extensions(arguments);
    }

    private Extensions(Extension.CreateInputArguments arguments) {
        ServiceLoader<Extension> extensionLoader = ServiceLoader.load(Extension.class);
        for (Extension extension : extensionLoader) {
            Extension.MakeCredentialProcessingResult result = extension.makeCredential(arguments);

            if (result != null) {
                mcContinuations.add(result.continuation);
                if (result.getAuthenticatorInput() != null) {
                    permissions |= result.getAuthenticatorPermissions();
                    authenticatorInput.putAll(result.getAuthenticatorInput().toMap());
                }
            }
        }
    }

    private Extensions(Extension.GetInputArguments arguments) {
        ServiceLoader<Extension> extensionLoader = ServiceLoader.load(Extension.class);
        for (Extension extension : extensionLoader) {
            Extension.GetAssertionProcessingResult result = extension.getAssertion(arguments);

            if (result != null) {
                gaContinuations.add(result.continuationProcessing);
                if (result.authenticatorInput != null) {
                    permissions |= result.authenticatorPermissions;
                    authenticatorInput.putAll(result.authenticatorInput.toMap());
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

    public ClientExtensionResults getResults(AttestationObject attestationObject) {
        ClientExtensionResults extensionExtensionResults = new ClientExtensionResults();

        for (Extension.MakeCredentialContinuation continuation : mcContinuations) {
            Extension.ExtensionResult result = continuation.processOutput(attestationObject);
            if (result != null) {
                extensionExtensionResults.add(result.toMap());
            }
        }

        return extensionExtensionResults;
    }

    public ClientExtensionResults getResults(Ctap2Session.AssertionData assertionData) {
        ClientExtensionResults extensionExtensionResults = new ClientExtensionResults();

        for (Extension.GetAssertionContinuation continuation : gaContinuations) {
            Extension.ExtensionResult result = continuation.processOutputs(assertionData);
            if (result != null) {
                extensionExtensionResults.add(result.toMap());
            }
        }

        return extensionExtensionResults;
    }
}

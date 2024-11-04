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

import javax.annotation.Nullable;

// Client Extension processing
public class Extensions {
    final List<Extension> usedExtensions = new ArrayList<>();
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Extensions.class);

    final Map<String, Object> authenticatorInput = new HashMap<>();
    int permissions = ClientPin.PIN_PERMISSION_NONE;

    public static Extensions processExtensions(Ctap2Session ctap, Extension.CreateInputArguments arguments) {
        return new Extensions(e -> e.processInput(arguments));
    }

    public static Extensions processExtensions(Ctap2Session ctap, Extension.GetInputArguments arguments) {
        return new Extensions(e -> e.processInput(arguments));
    }

    private Extensions(InputArgumentsProcessor processor) {
        ServiceLoader<Extension> extensionLoader = ServiceLoader.load(Extension.class);
        for (Extension extension : extensionLoader) {
            Extension.ProcessingResult result = processor.process(extension);

            if (result != null) {
                usedExtensions.add(extension);
                if (result.hasData()) {
                    permissions |= result.getPermissions();
                    authenticatorInput.putAll(result.getData());
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
            Extension.ProcessingResult result = processor.process(extension);
            if (result != null) {
                if (result.hasData()) {
                    extensionExtensionResults.add(result.getData());
                }
            }
        }

        return extensionExtensionResults;
    }

    interface InputArgumentsProcessor {
        @Nullable
        Extension.ProcessingResult process(Extension extension);
    }

    interface OutputArgumentsProcessor {
        @Nullable
        Extension.ProcessingResult process(Extension extension);
    }
}

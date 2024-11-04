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
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nullable;

public abstract class Extension {
    protected final String name;

    protected Extension(String name) {
        this.name = name;
    }

    boolean isSupported(Ctap2Session ctap) {
        return ctap.getCachedInfo().getExtensions().contains(name);
    }

    @Nullable
    ProcessingResult processInput(CreateInputArguments ignoredArguments) {
        return null;
    }

    @Nullable
    ProcessingResult processOutput(AttestationObject ignoredAttestationObject) {
        return null;
    }

    @Nullable
    ProcessingResult processOutput(
            AttestationObject attestationObject,
            CreateOutputArguments ignoredArguments) {
        return processOutput(attestationObject);
    }

    @Nullable
    ProcessingResult processInput(GetInputArguments ignoredArguments) {
        return null;
    }

    @Nullable
    ProcessingResult processOutput(Ctap2Session.AssertionData ignoredAssertionData) {
        return null;
    }

    @Nullable
    ProcessingResult processOutput(
            Ctap2Session.AssertionData assertionData,
            GetOutputArguments ignoredArguments) {
        return processOutput(assertionData);
    }

    public static class CreateInputArguments {
        final Ctap2Session ctap;
        final PublicKeyCredentialCreationOptions creationOptions;

        public CreateInputArguments(
                Ctap2Session ctap,
                PublicKeyCredentialCreationOptions creationOptions) {
            this.ctap = ctap;
            this.creationOptions = creationOptions;
        }

        PublicKeyCredentialCreationOptions getCreationOptions() {
            return creationOptions;
        }
    }

    public static class CreateOutputArguments {
        @Nullable final byte[] authToken;
        @Nullable final PinUvAuthProtocol pinUvAuthProtocol;

        public CreateOutputArguments(
                @Nullable byte[] authToken,
                @Nullable PinUvAuthProtocol pinUvAuthProtocol) {
            this.authToken = authToken;
            this.pinUvAuthProtocol = pinUvAuthProtocol;
        }
    }

    public static class GetInputArguments {
        final Ctap2Session ctap;
        final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

        final ClientPin clientPin;

        @Nullable final PublicKeyCredentialDescriptor selectedCredential;

        public GetInputArguments(
                Ctap2Session ctap,
                PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                ClientPin clientPin,
                @Nullable
                PublicKeyCredentialDescriptor selectedCredential) {
            this.ctap = ctap;
            this.publicKeyCredentialRequestOptions = publicKeyCredentialRequestOptions;
            this.clientPin = clientPin;
            this.selectedCredential = selectedCredential;
        }

        PublicKeyCredentialRequestOptions getPublicKeyCredentialRequestOptions() {
            return publicKeyCredentialRequestOptions;
        }

        public ClientPin getClientPin() {
            return clientPin;
        }

        @Nullable
        public PublicKeyCredentialDescriptor getSelectedCredential() {
            return selectedCredential;
        }
    }

    public static class GetOutputArguments {
        final Ctap2Session ctap;
        private final ClientPin clientPin;
        @Nullable
        private final byte[] authToken;
        @Nullable
        private final PinUvAuthProtocol pinUvAuthProtocol;

        public GetOutputArguments(
                Ctap2Session ctap,
                ClientPin clientPin, @Nullable byte[] authToken,
                @Nullable PinUvAuthProtocol pinUvAuthProtocol) {
            this.ctap = ctap;
            this.clientPin = clientPin;
            this.authToken = authToken;
            this.pinUvAuthProtocol = pinUvAuthProtocol;
        }

        public ClientPin getClientPin() {
            return clientPin;
        }

        @Nullable
        public byte[] getAuthToken() {
            return authToken;
        }

        @Nullable
        public PinUvAuthProtocol getPinUvAuthProtocol() {
            return pinUvAuthProtocol;
        }
    }

    /**
     * Builds an extension processing result without any data
     * @return empty ProcessingResult
     */
    ProcessingResult resultWithoutData() {
        return new ProcessingResult(null);
    }

    /**
     * Builds an extension processing result with data
     * @param name identifies the target extension
     * @param data data for target extension
     * @return initialized ProcessingResult object
     */
    ProcessingResult resultWithData(String name, Object data) {
        return resultWithDataAndPermission(name, data, ClientPin.PIN_PERMISSION_NONE);
    }

    /**
     * Builds an extension processing result with data and permissions
     * @param name identifies the target extension
     * @param data data for target extension
     * @param permissions result permissions
     * @return initialized ProcessingResult object
     */
    ProcessingResult resultWithDataAndPermission(String name, Object data, int permissions) {
        return new ProcessingResult(Collections.singletonMap(name, data), permissions);
    }

    /**
     * Result of extension input or output processing
     */
    static class ProcessingResult {
        private final Map<String, Object> data;
        private final boolean hasData;
        private final int permissions;

        private ProcessingResult(@Nullable Map<String, Object> data, int permissions) {
            this.data = data != null
                ? data
                : new HashMap<>();
            this.hasData = data != null;
            this.permissions = permissions;
        }

        private ProcessingResult(@Nullable Map<String, Object> data) {
            this(data, ClientPin.PIN_PERMISSION_NONE);
        }

        public Map<String, Object> getData() {
            return data;
        }

        public boolean hasData() {
            return hasData;
        }

        public int getPermissions() {
            return permissions;
        }
    }
}

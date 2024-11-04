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
import java.util.Map;

import javax.annotation.Nullable;

public class Extension {
    protected final String name;
    protected final Ctap2Session ctap;

    @Nullable
    private Map<String, Object> authenticatorInput = null;
    private int permissions = ClientPin.PIN_PERMISSION_NONE;

    protected Extension(String name, final Ctap2Session ctap) {
        this.name = name;
        this.ctap = ctap;
    }

    boolean isSupported() {
        return ctap.getCachedInfo().getExtensions().contains(name);
    }

    boolean processInput(
            CreateInputArguments ignoredCreateInputParameters) {
        return false;
    }

    @Nullable
    Map<String, Object> processOutput(AttestationObject ignoredAttestationObject) {
        return null;
    }

    @Nullable
    Map<String, Object> processOutput(
            AttestationObject attestationObject,
            CreateOutputArguments ignoredParameters) {
        return processOutput(attestationObject);
    }

    boolean processInput(GetInputArguments ignoredParameters) {
        return false;
    }

    @Nullable
    Map<String, Object> processOutput(Ctap2Session.AssertionData ignoredAssertionData) {
        return null;
    }

    @Nullable
    Map<String, Object> processOutput(
            Ctap2Session.AssertionData assertionData,
            GetOutputArguments ignoredParameters) {
        return processOutput(assertionData);
    }

    @Nullable
    Map<String, Object> getAuthenticatorInput() {
        return authenticatorInput;
    }

    public int getPermissions() {
        return permissions;
    }

    boolean withAuthenticatorInput(@Nullable Object authenticatorInput) {
        return withAuthenticatorInputAndPermissions(authenticatorInput, ClientPin.PIN_PERMISSION_NONE);
    }

    boolean withAuthenticatorInputAndPermissions(@Nullable Object authenticatorInput,
                                                 @Nullable Integer permissions) {
        if (permissions != null) {
            this.permissions = permissions;
        }

        this.authenticatorInput = Collections.singletonMap(name, authenticatorInput);

        return true;
    }

    boolean unused() {
        return false;
    }

    public interface InputArguments {}

    public static class CreateInputArguments implements InputArguments {
        final PublicKeyCredentialCreationOptions creationOptions;

        public CreateInputArguments(PublicKeyCredentialCreationOptions creationOptions) {
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

    public static class GetInputArguments implements InputArguments {
        final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

        final ClientPin clientPin;

        @Nullable final PublicKeyCredentialDescriptor selectedCredential;

        public GetInputArguments(
                PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                ClientPin clientPin,
                @Nullable
                PublicKeyCredentialDescriptor selectedCredential) {
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
        private final ClientPin clientPin;
        @Nullable
        private final byte[] authToken;
        @Nullable
        private final PinUvAuthProtocol pinUvAuthProtocol;

        public GetOutputArguments(
                ClientPin clientPin, @Nullable byte[] authToken,
                @Nullable PinUvAuthProtocol pinUvAuthProtocol) {
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
}

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

import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;

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
    MakeCredentialProcessingResult makeCredential(CreateInputArguments ignoredArguments) {
        return null;
    }

    @Nullable
    GetAssertionProcessingResult getAssertion(GetInputArguments ignoredArguments) {
        return null;
    }

    public static class CreateInputArguments {
        private final Ctap2Session ctap;
        private final PublicKeyCredentialCreationOptions creationOptions;

        public CreateInputArguments(
                Ctap2Session ctap,
                PublicKeyCredentialCreationOptions creationOptions) {
            this.ctap = ctap;
            this.creationOptions = creationOptions;
        }

        PublicKeyCredentialCreationOptions getCreationOptions() {
            return creationOptions;
        }

        public Ctap2Session getCtap() {
            return ctap;
        }
    }

    public interface AuthParamsProvider {
        @Nullable Pair<PinUvAuthProtocol, byte[]> getProtocolAndToken(int permissions);
    }

    public static class GetInputArguments {
        private final Ctap2Session ctap;
        private final PublicKeyCredentialRequestOptions requestOptions;
        private final AuthParamsProvider authParamsProvider;
        final ClientPin clientPin;
        @Nullable
        final PublicKeyCredentialDescriptor selectedCredential;

        public GetInputArguments(
                Ctap2Session ctap,
                PublicKeyCredentialRequestOptions requestOptions,
                AuthParamsProvider authParamsProvider,
                ClientPin clientPin,
                @Nullable PublicKeyCredentialDescriptor selectedCredential) {
            this.ctap = ctap;
            this.requestOptions = requestOptions;
            this.authParamsProvider = authParamsProvider;
            this.clientPin = clientPin;
            this.selectedCredential = selectedCredential;
        }

        public Ctap2Session getCtap() {
            return ctap;
        }

        PublicKeyCredentialRequestOptions getRequestOptions() {
            return requestOptions;
        }

        public AuthParamsProvider getAuthParamsProvider() {
            return authParamsProvider;
        }

        public ClientPin getClientPin() {
            return clientPin;
        }

        @Nullable
        public PublicKeyCredentialDescriptor getSelectedCredential() {
            return selectedCredential;
        }
    }

    interface AuthenticatorInput {
        Map<String, Object> toMap();
    }

    interface ExtensionResult {
        Map<String, Object> toMap();
    }

    interface MakeCredentialContinuation {
        @Nullable ExtensionResult processOutput(AttestationObject attestationObject);
    }

    interface GetAssertionContinuation {
        @Nullable ExtensionResult processOutputs(Ctap2Session.AssertionData assertionData);
    }

    static class MakeCredentialProcessingResult {
        @Nullable
        private final AuthenticatorInput authenticatorInput;
        private final int authenticatorPermissions;

        final MakeCredentialContinuation continuation;

        MakeCredentialProcessingResult(@Nullable AuthenticatorInput authenticatorInput) {
            this(authenticatorInput, ClientPin.PIN_PERMISSION_NONE, attestationObject -> null);
        }

        MakeCredentialProcessingResult(
                @Nullable AuthenticatorInput authenticatorInput,
                MakeCredentialContinuation continuation
        ) {
            this(authenticatorInput, ClientPin.PIN_PERMISSION_NONE, continuation);
        }

        MakeCredentialProcessingResult(
                @Nullable AuthenticatorInput authenticatorInput,
                int authenticatorPermissions,
                MakeCredentialContinuation continuation
        ) {
            this.authenticatorInput = authenticatorInput;
            this.authenticatorPermissions = authenticatorPermissions;
            this.continuation = continuation;
        }

        MakeCredentialProcessingResult(MakeCredentialContinuation continuation) {
            this(null, continuation);
        }

        boolean hasAuthenticatorInput() {
            return authenticatorInput != null;
        }


        @Nullable
        public AuthenticatorInput getAuthenticatorInput() {
            return authenticatorInput;
        }

        public int getAuthenticatorPermissions() {
            return authenticatorPermissions;
        }

        public MakeCredentialContinuation getContinuation() {
            return continuation;
        }
    }

    static class GetAssertionProcessingResult {
        @Nullable
        final AuthenticatorInput authenticatorInput;
        final int authenticatorPermissions;
        final GetAssertionContinuation continuationProcessing;

        GetAssertionProcessingResult(
                @Nullable AuthenticatorInput authenticatorInput
        ) {
            this(authenticatorInput, ClientPin.PIN_PERMISSION_NONE, assertionData -> null);
        }


        GetAssertionProcessingResult(
                @Nullable AuthenticatorInput authenticatorInput,
                GetAssertionContinuation continuation
        ) {
            this(authenticatorInput, ClientPin.PIN_PERMISSION_NONE, continuation);
        }

        GetAssertionProcessingResult(
                @Nullable AuthenticatorInput authenticatorInput,
                int authenticatorPermissions,
                GetAssertionContinuation continuation
        ) {
            this.authenticatorInput = authenticatorInput;
            this.authenticatorPermissions = authenticatorPermissions;
            this.continuationProcessing = continuation;
        }

        boolean hasAuthenticatorInput() {
            return authenticatorInput != null;
        }
    }
}

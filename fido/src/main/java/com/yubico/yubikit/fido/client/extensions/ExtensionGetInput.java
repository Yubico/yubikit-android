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
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;

import javax.annotation.Nullable;

public class ExtensionGetInput {
    final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    final ClientPin clientPin;

    @Nullable final PublicKeyCredentialDescriptor selectedCredential;

    public ExtensionGetInput(
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

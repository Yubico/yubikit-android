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
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;

import javax.annotation.Nullable;

public class ExtensionGetOutput {
    private final ClientPin clientPin;
    @Nullable
    private final byte[] authToken;
    @Nullable
    private final PinUvAuthProtocol pinUvAuthProtocol;

    public ExtensionGetOutput(
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

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

import java.util.Collections;
import java.util.Map;

import javax.annotation.Nullable;

class ExtensionInput {
    @Nullable
    private final Map<String, Object> authenticatorInput;
    private final int requiredPermissions;
    private final boolean isUsed;

    static ExtensionInput unused() {
        return new ExtensionInput(false);
    }

    static ExtensionInput withoutInput() {
        return new ExtensionInput(true);
    }

    static ExtensionInput withAuthenticatorInput(String name, Object data) {
        return withAuthenticatorInput(name, data, ClientPin.PIN_PERMISSION_NONE);
    }

    static ExtensionInput withAuthenticatorInput(String name, Object data, int permissions) {
        return new ExtensionInput(name, data, permissions);
    }

    private ExtensionInput(boolean isUsed) {
        this.isUsed = isUsed;
        this.authenticatorInput = null;
        this.requiredPermissions = 0;
    }

    private ExtensionInput(String name, Object data, int permissions) {
        this.authenticatorInput = Collections.singletonMap(name, data);
        this.requiredPermissions = permissions;
        this.isUsed = true;
    }

    @Nullable
    public Map<String, Object> getAuthenticatorInput() {
        return authenticatorInput;
    }

    public int getRequiredPermissions() {
        return requiredPermissions;
    }

    public boolean isUsed() {
        return isUsed;
    }
}

/*
 * Copyright (C) 2020-2023 Yubico.
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

import static com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor.ID;

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAssertionResponse;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nullable;

class ConversionUtils {
    static PublicKeyCredentialUserEntity publicKeyCredentialUserEntityFromMap(Map<String, ?> user) {
        return new PublicKeyCredentialUserEntity(
                Objects.requireNonNull((String) user.get(PublicKeyCredentialUserEntity.NAME)),
                Objects.requireNonNull((byte[]) user.get(PublicKeyCredentialUserEntity.ID)),
                Objects.requireNonNull((String) user.get(PublicKeyCredentialUserEntity.DISPLAY_NAME)));
    }

    static Map<String, Object> publicKeyCredentialUserEntityToMap(PublicKeyCredentialUserEntity userEntity) {
        final Map<String, Object> user = new HashMap<>();
        user.put(PublicKeyCredentialUserEntity.NAME, userEntity.getName());
        user.put(PublicKeyCredentialUserEntity.ID, userEntity.getId());
        user.put(PublicKeyCredentialUserEntity.DISPLAY_NAME, userEntity.getDisplayName());
        return user;
    }

    static PublicKeyCredentialDescriptor publicKeyCredentialDescriptorFromMap(Map<String, ?> credential) {
        return new PublicKeyCredentialDescriptor(
                Objects.requireNonNull((String) credential.get(PublicKeyCredentialDescriptor.TYPE)),
                Objects.requireNonNull((byte[]) credential.get(ID))
        );
    }

    static Map<String, Object> publicKeyCredentialDescriptorToMap(PublicKeyCredentialDescriptor credentialDescriptor) {
        Map<String, Object> credentialDescriptorMap = new HashMap<>();
        credentialDescriptorMap.put(PublicKeyCredentialDescriptor.TYPE, credentialDescriptor.getType());
        credentialDescriptorMap.put(ID, credentialDescriptor.getId());
        return credentialDescriptorMap;
    }
}

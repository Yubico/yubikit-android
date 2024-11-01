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

import static com.yubico.yubikit.core.internal.codec.Base64.fromUrlSafeString;

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.Extensions;

class CredBlobExtension extends Extension {
    CredBlobExtension(final Ctap2Session ctap) {
        super("credBlob", ctap);
    }

    @Override
    ExtensionInput processInput(ExtensionCreateInput parameters) {

        Extensions extensions = parameters.creationOptions.getExtensions();
        if (isSupported()) {
            String b64Blob = (String) extensions.get("credBlob");
            if (b64Blob != null) {
                byte[] blob = fromUrlSafeString(b64Blob);
                if (blob.length <= ctap.getCachedInfo().getMaxCredBlobLength()) {
                    return extensionInput(blob);
                }
            }
        }
        return ExtensionInput.unused();
    }

    @Override
    ExtensionInput processInput(ExtensionGetInput parameters) {
        Extensions extensions = parameters.publicKeyCredentialRequestOptions.getExtensions();
        if (isSupported() && Boolean.TRUE.equals(extensions.get("getCredBlob"))) {
            return extensionInput(true);
        }
        return ExtensionInput.unused();
    }
}

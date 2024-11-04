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
import static com.yubico.yubikit.core.internal.codec.Base64.toUrlSafeString;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.Extensions;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Map;

import javax.annotation.Nullable;

class LargeBlobExtension extends Extension {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(com.yubico.yubikit.fido.client.extensions.LargeBlobExtension.class);

    @Nullable private Object action = null;

    public LargeBlobExtension(final Ctap2Session ctap) {
        super("largeBlobKey", ctap);
    }

    @Override
    boolean isSupported() {
        return super.isSupported() && ctap.getCachedInfo().getOptions()
                .containsKey("largeBlobs");
    }

    @Override
    boolean processInput(CreateInputArguments arguments) {

        Extensions extensions = arguments.creationOptions.getExtensions();
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) extensions.get("largeBlob");
        if (data != null) {
            if (data.containsKey("read") || data.containsKey("write")) {
                throw new IllegalArgumentException("Invalid set of parameters");
            }
            if ("required".equals(data.get("support")) && !isSupported()) {
                throw new IllegalArgumentException("Authenticator does not support large" +
                        " blob storage");
            }
            return withAuthenticatorInput(true);
        }
        return unused();
    }

    @Nullable
    @Override
    Map<String, Object> processOutput(
            Ctap2Session.AssertionData assertionData,
            GetOutputArguments arguments) {

        byte[] largeBlobKey = assertionData.getLargeBlobKey();
        if (largeBlobKey == null) {
            return null;
        }

        try {
            if (Boolean.TRUE.equals(action)) {
                LargeBlobs largeBlobs = new LargeBlobs(ctap);
                byte[] blob = largeBlobs.getBlob(largeBlobKey);
                return Collections.singletonMap("largeBlob",
                        blob != null
                                ? Collections.singletonMap("blob", toUrlSafeString(blob))
                                : Collections.emptyMap());
            } else if (action != null && action instanceof byte[]) {
                byte[] bytes = (byte[]) action;
                LargeBlobs largeBlobs = new LargeBlobs(
                        ctap,
                        arguments.getPinUvAuthProtocol(),
                        arguments.getAuthToken());
                largeBlobs.putBlob(largeBlobKey, bytes);

                return Collections.singletonMap("largeBlob",
                        Collections.singletonMap("written", true));
            }
        } catch (IOException | CommandException | GeneralSecurityException e) {
            Logger.error(logger, "LargeBlob processing failed: ", e);
        }

        return null;
    }

    @SuppressWarnings("unchecked")
    @Override
    boolean processInput(GetInputArguments arguments) {

        Extensions extensions = arguments.publicKeyCredentialRequestOptions.getExtensions();

        Map<String, Object> data = (Map<String, Object>) extensions.get("largeBlob");
        if (data != null && data.containsKey("read")) {
            action = data.get("read");
            return withAuthenticatorInput(true);
        } else if (data != null && data.containsKey("write")) {
            action = fromUrlSafeString((String) data.get("write"));
            return withAuthenticatorInputAndPermissions(true, ClientPin.PIN_PERMISSION_LBW);
        }
        return unused();
    }

    @Nullable
    @Override
    Map<String, Object> processOutput(AttestationObject attestationObject) {
        return Collections.singletonMap("largeBlob",
                Collections.singletonMap("supported",
                        attestationObject.getLargeBlobKey() != null));
    }
}

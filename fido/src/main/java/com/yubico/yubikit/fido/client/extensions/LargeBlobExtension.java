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
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.Extensions;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.Map;

import javax.annotation.Nullable;

public class LargeBlobExtension extends Extension {
    private static final String LARGE_BLOB_KEY = "largeBlobKey";
    private static final String LARGE_BLOB = "largeBlob";
    private static final String LARGE_BLOBS = "largeBlobs";
    private static final String ACTION_READ = "read";
    private static final String ACTION_WRITE = "write";
    private static final String WRITTEN = "written";
    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(com.yubico.yubikit.fido.client.extensions.LargeBlobExtension.class);

    public LargeBlobExtension() {
        super(LARGE_BLOB_KEY);
    }

    @Override
    boolean isSupported(Ctap2Session ctap) {
        return super.isSupported(ctap) && ctap.getCachedInfo().getOptions()
                .containsKey(LARGE_BLOBS);
    }

    @Override
    MakeCredentialProcessingResult makeCredential(CreateInputArguments arguments) {

        Extensions extensions = arguments.getCreationOptions().getExtensions();
        @SuppressWarnings("unchecked")
        Map<String, Object> data = (Map<String, Object>) extensions.get(LARGE_BLOB);
        if (data != null) {
            if (data.containsKey(ACTION_READ) || data.containsKey(ACTION_WRITE)) {
                throw new IllegalArgumentException("Invalid set of parameters");
            }
            if ("required".equals(data.get("support")) && !isSupported(arguments.getCtap())) {
                throw new IllegalArgumentException("Authenticator does not support large" +
                        " blob storage");
            }
            return new MakeCredentialProcessingResult(
                    () -> Collections.singletonMap(LARGE_BLOB, true),
                    this::makeCredentialOutput
            );
        }
        return null;
    }


    @SuppressWarnings("unchecked")
    @Override
    GetAssertionProcessingResult getAssertion(GetInputArguments arguments) {

        Extensions extensions = arguments.getRequestOptions().getExtensions();

        Map<String, Object> data = (Map<String, Object>) extensions.get(LARGE_BLOB);
        if (data != null && data.containsKey(ACTION_READ)) {
            return new GetAssertionProcessingResult(
                    () -> Collections.singletonMap(LARGE_BLOB, true),
                    assertionData -> read(assertionData, arguments)
            );
        } else if (data != null && data.containsKey(ACTION_WRITE)) {
            return new GetAssertionProcessingResult(
                    () -> Collections.singletonMap(LARGE_BLOB, true),
                    ClientPin.PIN_PERMISSION_LBW,
                    assertionData -> write(assertionData, arguments,
                            fromUrlSafeString((String) data.get(ACTION_WRITE))));
        }
        return null;
    }

    @Nullable
    ExtensionResult read(
            Ctap2Session.AssertionData assertionData,
            GetInputArguments arguments) {

        byte[] largeBlobKey = assertionData.getLargeBlobKey();
        if (largeBlobKey == null) {
            return null;
        }

        try {
            LargeBlobs largeBlobs = new LargeBlobs(arguments.getCtap());
            byte[] blob = largeBlobs.getBlob(largeBlobKey);
            return () -> Collections.singletonMap(LARGE_BLOB, blob != null
                    ? Collections.singletonMap("blob", toUrlSafeString(blob))
                    : Collections.emptyMap());
        } catch (IOException | CommandException e) {
            Logger.error(logger, "LargeBlob processing failed: ", e);
        }

        return null;
    }

    @Nullable
    ExtensionResult write(
            Ctap2Session.AssertionData assertionData,
            GetInputArguments arguments,
            byte[] bytes) {

        byte[] largeBlobKey = assertionData.getLargeBlobKey();
        if (largeBlobKey == null) {
            return null;
        }

        try {
            Pair<PinUvAuthProtocol, byte[]> authParams = arguments
                    .getAuthParamsProvider()
                    .getProtocolAndToken(ClientPin.PIN_PERMISSION_LBW | ClientPin.PIN_PERMISSION_GA);
            if (authParams == null) {
                return null;
            }
            LargeBlobs largeBlobs = new LargeBlobs(
                    arguments.getCtap(),
                    authParams.first,
                    authParams.second);
            largeBlobs.putBlob(largeBlobKey, bytes);

            return () -> Collections.singletonMap(LARGE_BLOB, Collections.singletonMap(WRITTEN, true));

        } catch (IOException | CommandException | GeneralSecurityException e) {
            Logger.error(logger, "LargeBlob processing failed: ", e);
        }

        return null;
    }

    @Nullable
    ExtensionResult makeCredentialOutput(AttestationObject attestationObject) {
        return () -> Collections.singletonMap(LARGE_BLOB,
                Collections.singletonMap("supported",
                        attestationObject.getLargeBlobKey() != null));
    }
}

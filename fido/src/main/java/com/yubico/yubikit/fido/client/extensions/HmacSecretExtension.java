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
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorData;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.Nullable;

class HmacSecretExtension extends Extension {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(HmacSecretExtension.class);

    private boolean prf = false;
    private static final int SALT_LEN = 32;
    private byte[] sharedSecret;

    private static class Salts {
        byte[] salt1;
        byte[] salt2;

        Salts(byte[] salt1, @Nullable byte[] salt2) {
            this.salt1 = salt1;
            this.salt2 = salt2 != null ? salt2 : new byte[0];
        }
    }

    @Nullable
    private byte[] prfSalt(@Nullable byte[] secret) {
        try {
            return secret == null
                    ? null
                    : MessageDigest.getInstance("SHA-256").digest(
                    ByteBuffer
                            .allocate(13 + secret.length)
                            .put("WebAuthn PRF".getBytes(StandardCharsets.US_ASCII))
                            .put((byte) 0x00)
                            .put(secret)
                            .array());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 missing", e);
        }
    }

    HmacSecretExtension(final Ctap2Session ctap) {
        super("hmac-secret", ctap);
    }

    @Override
    boolean processInput(CreateInputArguments arguments) {
        Extensions extensions = arguments.creationOptions.getExtensions();
        if (Boolean.TRUE.equals(extensions.get("hmacCreateSecret"))) {
            prf = false;
            return withAuthenticatorInput(true);
        } else if (extensions.has("prf")) {
            prf = true;
            return withAuthenticatorInput(true);
        }
        return unused();
    }

    @Nullable
    @Override
    Map<String, Object> processOutput(AttestationObject attestationObject) {
        Map<String, ?> extensions = attestationObject.getAuthenticatorData().getExtensions();

        boolean enabled = extensions != null && Boolean.TRUE.equals(extensions.get(name));
        return prf
                ? Collections.singletonMap("prf", Collections.singletonMap("enabled", enabled))
                : Collections.singletonMap("hmacCreateSecret", enabled);
    }

    @SuppressWarnings("unchecked")
    @Override
    boolean processInput(GetInputArguments arguments) {
        if (!isSupported()) {
            return false;
        }

        Extensions extensions = arguments.publicKeyCredentialRequestOptions.getExtensions();
        Salts salts;
        Map<String, Object> data = (Map<String, Object>) extensions.get("prf");
        if (data != null) {
            Map<String, Object> secrets = (Map<String, Object>) data.get("eval");
            Map<String, Object> evalByCredential =
                    (Map<String, Object>) data.get("evalByCredential");

            if (evalByCredential != null) {
                List<PublicKeyCredentialDescriptor> allowCredentials =
                        arguments.publicKeyCredentialRequestOptions.getAllowCredentials();

                if (allowCredentials.isEmpty()) {
                    throw new IllegalArgumentException("evalByCredential needs allow list");
                }

                Set<String> ids = allowCredentials
                        .stream()
                        .map(desc -> toUrlSafeString(desc.getId()))
                        .collect(Collectors.toSet());

                if (!ids.containsAll(evalByCredential.keySet())) {
                    throw new IllegalArgumentException("evalByCredentials contains invalid key");
                }

                if (arguments.selectedCredential != null) {
                    String key = toUrlSafeString(arguments.selectedCredential.getId());
                    if (evalByCredential.containsKey(key)) {
                        secrets = (Map<String, Object>) evalByCredential.get(key);
                    }
                }
            }

            if (secrets == null) {
                return false;
            }

            Logger.debug(logger, "PRF inputs: {}, {}", secrets.get("first"), secrets.get("second"));

            String firstInput = (String) secrets.get("first");
            if (firstInput == null) {
                return false;
            }

            byte[] first = fromUrlSafeString(firstInput);

            byte[] second = secrets.containsKey("second")
                    ? prfSalt(fromUrlSafeString((String) secrets.get("second")))
                    : null;

            salts = new Salts(prfSalt(first), second);
            prf = true;
        } else {
            data = (Map<String, Object>) extensions.get("hmacGetSecret");
            if (data == null) {
                return false;
            }

            Logger.debug(logger, "hmacGetSecret inputs: {}, {}", data.get("salt1"), data.get("salt2"));

            byte[] salt1 = fromUrlSafeString((String) Objects.requireNonNull(data.get("salt1")));

            byte[] salt2 = data.containsKey("salt2")
                    ? prfSalt(fromUrlSafeString((String) data.get("salt2")))
                    : null;

            salts = new Salts(prfSalt(salt1), prfSalt(salt2));
            prf = false;
        }

        Logger.debug(logger, "Salts: {}, {}", StringUtils.bytesToHex(salts.salt1), StringUtils.bytesToHex(salts.salt2));
        if (!(salts.salt1.length == SALT_LEN &&
                (salts.salt2.length == 0 || salts.salt2.length == SALT_LEN))) {
            throw new IllegalArgumentException("Invalid salt length");
        }

        final ClientPin clientPin = arguments.getClientPin();

        try {
            Pair<Map<Integer, ?>, byte[]> keyAgreement = clientPin.getSharedSecret();

            this.sharedSecret = keyAgreement.second;

            byte[] saltEnc = clientPin.getPinUvAuth().encrypt(
                    sharedSecret,
                    ByteBuffer
                            .allocate(salts.salt1.length + salts.salt2.length)
                            .put(salts.salt1)
                            .put(salts.salt2)
                            .array());

            byte[] saltAuth = clientPin.getPinUvAuth().authenticate(
                    keyAgreement.second,
                    saltEnc);

            final Map<Integer, Object> hmacGetSecretInput = new HashMap<>();
            hmacGetSecretInput.put(1, keyAgreement.first);
            hmacGetSecretInput.put(2, saltEnc);
            hmacGetSecretInput.put(3, saltAuth);
            hmacGetSecretInput.put(4, clientPin.getPinUvAuth().getVersion());
            return withAuthenticatorInput(hmacGetSecretInput);
        } catch (IOException | CommandException e) {
            return unused();
        }
    }

    @Nullable
    @Override
    Map<String, Object> processOutput(
            Ctap2Session.AssertionData assertionData,
            GetOutputArguments arguments) {

        AuthenticatorData authenticatorData = AuthenticatorData.parseFrom(ByteBuffer.wrap(
                assertionData.getAuthenticatorData()
        ));

        Map<String, ?> extensionOutputs = authenticatorData.getExtensions();
        if (extensionOutputs == null) {
            return null;
        }

        byte[] value = (byte[]) extensionOutputs.get(name);
        if (value == null) {
            return null;
        }

        final ClientPin clientPin = arguments.getClientPin();
        byte[] decrypted = clientPin.getPinUvAuth().decrypt(sharedSecret, value);

        byte[] output1 = Arrays.copyOf(decrypted, SALT_LEN);
        byte[] output2 = decrypted.length > SALT_LEN
                ? Arrays.copyOfRange(decrypted, SALT_LEN, 2 * SALT_LEN)
                : new byte[0];

        Logger.debug(logger, "Decrypted:  {}, o1: {}, o2: {}",
                StringUtils.bytesToHex(decrypted),
                StringUtils.bytesToHex(output1),
                StringUtils.bytesToHex(output2));

        Map<String, Object> results = new HashMap<>();
        if (prf) {
            results.put("first", toUrlSafeString(output1));
            if (output2.length > 0) {
                results.put("second", toUrlSafeString(output2));
            }
            return Collections.singletonMap("prf",
                    Collections.singletonMap("results", results));
        } else {
            results.put("output1", toUrlSafeString(output1));
            if (output2.length > 0) {
                results.put("output2", toUrlSafeString(output2));
            }
            return Collections.singletonMap("hmacGetSecret", results);
        }
    }
}

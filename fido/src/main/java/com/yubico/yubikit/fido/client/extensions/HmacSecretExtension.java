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
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.Nullable;

public class HmacSecretExtension extends Extension {

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(HmacSecretExtension.class);
    private static final int SALT_LEN = 32;

    private static class Salts {
        byte[] salt1;
        byte[] salt2;

        Salts(byte[] salt1, @Nullable byte[] salt2) {
            this.salt1 = salt1;
            this.salt2 = salt2 != null ? salt2 : new byte[0];
        }
    }

    private byte[] prfSalt(byte[] secret) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(
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

    public HmacSecretExtension() {
        super("hmac-secret");
    }

    @Override
    MakeCredentialProcessingResult makeCredential(CreateInputArguments arguments) {
        Extensions extensions = arguments.getCreationOptions().getExtensions();
        if (Boolean.TRUE.equals(extensions.get("hmacCreateSecret"))) {
            return new MakeCredentialProcessingResult(
                    () -> Collections.singletonMap(name, true),
                    attestationObject -> makeCredentialOutput(attestationObject, false)
            );
        } else if (extensions.has("prf")) {
            return new MakeCredentialProcessingResult(
                    () -> Collections.singletonMap(name, true),
                    attestationObject -> makeCredentialOutput(attestationObject, true)
            );
        }
        return null;
    }

    @Nullable
    ExtensionResult makeCredentialOutput(AttestationObject attestationObject, boolean isPrf) {
        Map<String, ?> extensions = attestationObject.getAuthenticatorData().getExtensions();

        boolean enabled = extensions != null && Boolean.TRUE.equals(extensions.get(name));
        return isPrf
                ? () -> Collections.singletonMap("prf", Collections.singletonMap("enabled", enabled))
                : () -> Collections.singletonMap("hmacCreateSecret", enabled);
    }

    @SuppressWarnings("unchecked")
    @Override
    GetAssertionProcessingResult getAssertion(GetInputArguments arguments) {
        if (!isSupported(arguments.getCtap())) {
            return null;
        }

        Extensions extensions = arguments.getRequestOptions().getExtensions();
        Salts salts;
        Map<String, Object> data = (Map<String, Object>) extensions.get("prf");
        boolean isPrf;
        if (data != null) {
            Map<String, Object> secrets = (Map<String, Object>) data.get("eval");
            Map<String, Object> evalByCredential =
                    (Map<String, Object>) data.get("evalByCredential");

            if (evalByCredential != null) {
                List<PublicKeyCredentialDescriptor> allowCredentials =
                        arguments.getRequestOptions().getAllowCredentials();

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
                return null;
            }

            Logger.debug(logger, "PRF inputs: {}, {}", secrets.get("first"), secrets.get("second"));

            String firstInput = (String) secrets.get("first");
            if (firstInput == null) {
                return null;
            }

            byte[] first = prfSalt(fromUrlSafeString(firstInput));
            byte[] second = secrets.containsKey("second")
                    ? prfSalt(fromUrlSafeString((String) secrets.get("second")))
                    : null;

            salts = new Salts(first, second);
            isPrf = true;
        } else {
            data = (Map<String, Object>) extensions.get("hmacGetSecret");
            if (data == null) {
                return null;
            }

            Logger.debug(logger, "hmacGetSecret inputs: {}, {}", data.get("salt1"), data.get("salt2"));

            String salt1B64 = (String) data.get("salt1");
            if (salt1B64 == null) {
                return null;
            }

            byte[] salt1 = prfSalt(fromUrlSafeString(salt1B64));
            byte[] salt2 = data.containsKey("salt2")
                    ? prfSalt(fromUrlSafeString((String) data.get("salt2")))
                    : null;

            salts = new Salts(salt1, salt2);
            isPrf = false;
        }

        Logger.debug(logger, "Salts: {}, {}", StringUtils.bytesToHex(salts.salt1), StringUtils.bytesToHex(salts.salt2));
        if (!(salts.salt1.length == SALT_LEN &&
                (salts.salt2.length == 0 || salts.salt2.length == SALT_LEN))) {
            throw new IllegalArgumentException("Invalid salt length");
        }

        final ClientPin clientPin = arguments.getClientPin();

        try {
            Pair<Map<Integer, ?>, byte[]> keyAgreement = clientPin.getSharedSecret();

            byte[] saltEnc = clientPin.getPinUvAuth().encrypt(
                    keyAgreement.second,
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
            return new GetAssertionProcessingResult(
                    () -> Collections.singletonMap(name, hmacGetSecretInput),
                    assertionData -> getAssertion(assertionData, arguments, isPrf, keyAgreement.second)
            );
        } catch (IOException | CommandException e) {
            return null;
        }
    }

    @Nullable
    ExtensionResult getAssertion(
            Ctap2Session.AssertionData assertionData,
            GetInputArguments arguments,
            boolean isPrf,
            byte[] sharedSecret) {

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
        if (isPrf) {
            results.put("first", toUrlSafeString(output1));
            if (output2.length > 0) {
                results.put("second", toUrlSafeString(output2));
            }
            return () -> Collections.singletonMap("prf",
                    Collections.singletonMap("results", results));
        } else {
            results.put("output1", toUrlSafeString(output1));
            if (output2.length > 0) {
                results.put("output2", toUrlSafeString(output2));
            }
            return () -> Collections.singletonMap("hmacGetSecret", results);
        }
    }
}

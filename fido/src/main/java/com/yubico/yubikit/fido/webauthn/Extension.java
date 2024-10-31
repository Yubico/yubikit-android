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

package com.yubico.yubikit.fido.webauthn;

import static com.yubico.yubikit.fido.webauthn.SerializationUtils.deserializeBytes;
import static com.yubico.yubikit.fido.webauthn.SerializationUtils.serializeBytes;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.ext.LargeBlobs;
import com.yubico.yubikit.fido.webauthn.ext.SignExtension;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import javax.annotation.Nullable;

public class Extension {
    protected final String name;
    protected final Ctap2Session ctap;

    protected Extension(String name, final Ctap2Session ctap) {
        this.name = name;
        this.ctap = ctap;
    }

    public boolean isSupported() {
        return ctap.getCachedInfo().getExtensions().contains(name);
    }

    public String getName() {
        return name;
    }

    @Nullable
    protected CreateInputResult buildCreateInputResult(Object data) {
        return new CreateInputResult(getName(), data);
    }

    @Nullable
    protected CreateInputResult buildCreateInputResult(Object data, int permissions) {
        return new CreateInputResult(getName(), data, permissions);
    }

    @Nullable
    protected GetInputResult buildGetInputResult(Object data) {
        return new GetInputResult(getName(), data);
    }

    @Nullable
    protected GetInputResult buildGetInputResult(Object data, int permissions) {
        return new GetInputResult(getName(), data, permissions);
    }

    @Nullable
    public CreateInputResult processCreateInput(Map<String, ?> inputs) {
        return null;
    }

    @Nullable
    public CreateInputResult processCreateInput(Map<String, ?> inputs, CreateInputParameters createInputParameters) {
        return processCreateInput(inputs);
    }

    @Nullable
    public ExtensionResult processCreateOutput(AttestationObject ignoredAttestationObject) {
        return null;
    }

    @Nullable
    public ExtensionResult processCreateOutput(
            AttestationObject attestationObject,
            CreateOutputParameters ignoredParameters) {
        return processCreateOutput(attestationObject);
    }

    @Nullable
    public GetInputResult processGetInput(Map<String, ?> inputs) {
        return null;
    }

    @Nullable
    public GetInputResult processGetInput(Map<String, ?> inputs, GetInputParameters ignoredParameters) {
        return processGetInput(inputs);
    }

    @Nullable
    public ExtensionResult processGetOutput(Ctap2Session.AssertionData assertionData) {
        return null;
    }

    @Nullable
    public ExtensionResult processGetOutput(
            Ctap2Session.AssertionData assertionData,
            GetOutputParameters ignoredParameters) {
        return processGetOutput(assertionData);
    }

    static class HmacSecretExtension extends Extension {

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
            return secret == null
                    ? null
                    : hash(ByteBuffer
                    .allocate(13 + secret.length)
                    .put("WebAuthn PRF".getBytes(StandardCharsets.US_ASCII))
                    .put((byte) 0x00)
                    .put(secret)
                    .array());
        }

        public HmacSecretExtension(final Ctap2Session ctap) {
            super("hmac-secret", ctap);
        }

        @Nullable
        @Override
        public CreateInputResult processCreateInput(Map<String, ?> inputs) {
            if (Boolean.TRUE.equals(inputs.get("hmacCreateSecret"))) {
                prf = false;
                return buildCreateInputResult(true);
            } else if (inputs.get("prf") != null) {
                prf = true;
                return buildCreateInputResult(true);
            }
            return null;
        }

        @Nullable
        @Override
        public ExtensionResult processCreateOutput(AttestationObject attestationObject) {
            Map<String, ?> extensions = attestationObject.getAuthenticatorData().getExtensions();

            boolean enabled = extensions != null && Boolean.TRUE.equals(extensions.get(name));
            return new ExtensionResult(prf
                    ? Collections.singletonMap("prf", Collections.singletonMap("enabled", enabled))
                    : Collections.singletonMap("hmacCreateSecret", enabled));
        }

        @SuppressWarnings("unchecked")
        @Nullable
        @Override
        public GetInputResult processGetInput(Map<String, ?> inputs, GetInputParameters parameters) {
            if (!isSupported()) {
                return null;
            }

            Salts salts;
            Map<String, Object> data = (Map<String, Object>) inputs.get("prf");
            if (data != null) {
                Map<String, Object> secrets = (Map<String, Object>) data.get("eval");
                Map<String, Object> evalByCredential =
                        (Map<String, Object>) data.get("evalByCredential");

                if (evalByCredential != null) {
                    List<PublicKeyCredentialDescriptor> allowCredentials =
                            parameters.publicKeyCredentialRequestOptions.getAllowCredentials();

                    if (allowCredentials.isEmpty()) {
                        throw new IllegalArgumentException("evalByCredential needs allow list");
                    }

                    Set<String> ids = allowCredentials
                            .stream()
                            .map( desc ->
                                    (String) SerializationUtils.serializeBytes(
                                            desc.getId(), SerializationType.JSON))
                            .collect(Collectors.toSet());

                    if (!ids.containsAll(evalByCredential.keySet())) {
                        throw new IllegalArgumentException("evalByCredentials contains invalid key");
                    }

                    if (parameters.selectedCredential != null) {
                        String key = (String) SerializationUtils.serializeBytes(
                                parameters.selectedCredential.getId(), SerializationType.JSON);
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

                byte[] first = SerializationUtils.deserializeBytes(
                        Objects.requireNonNull(firstInput),
                        SerializationType.JSON);

                byte[] second = secrets.containsKey("second")
                        ? prfSalt(
                        SerializationUtils.deserializeBytes(
                                secrets.get("second"),
                                SerializationType.JSON
                        ))
                        : null;

                salts = new Salts(prfSalt(first), second);
                prf = true;
            } else {
                data = (Map<String, Object>) inputs.get("hmacGetSecret");
                if (data == null) {
                    return null;
                }

                Logger.debug(logger, "hmacGetSecret inputs: {}, {}", data.get("salt1"), data.get("salt2"));

                byte[] salt1 = SerializationUtils.deserializeBytes(
                        Objects.requireNonNull(data.get("salt1")),
                        SerializationType.JSON);

                byte[] salt2 = data.containsKey("salt2")
                        ? prfSalt(SerializationUtils.deserializeBytes(
                        data.get("salt2"),
                        SerializationType.JSON))
                        : null;

                salts = new Salts(prfSalt(salt1), prfSalt(salt2));
                prf = false;
            }

            Logger.debug(logger, "Salts: {}, {}", StringUtils.bytesToHex(salts.salt1), StringUtils.bytesToHex(salts.salt2));
            if (!(salts.salt1.length == SALT_LEN &&
                    (salts.salt2.length == 0 || salts.salt2.length == SALT_LEN))) {
                throw new IllegalArgumentException("Invalid salt length");
            }

            final ClientPin clientPin = parameters.getClientPin();

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
                return buildGetInputResult(hmacGetSecretInput);
            } catch (IOException | CommandException e) {
                return null;
            }
        }

        @Nullable
        @Override
        public ExtensionResult processGetOutput(
                Ctap2Session.AssertionData assertionData,
                GetOutputParameters parameters) {

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

            final ClientPin clientPin = parameters.getClientPin();
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
                results.put("first", SerializationUtils.serializeBytes(output1, SerializationType.JSON));
                if (output2.length > 0) {
                    results.put("second", SerializationUtils.serializeBytes(output2, SerializationType.JSON));
                }
                return new ExtensionResult(
                        Collections.singletonMap("prf",
                                Collections.singletonMap("results", results)));
            } else {
                results.put("output1", SerializationUtils.serializeBytes(output1, SerializationType.JSON));
                if (output2.length > 0) {
                    results.put("output2", SerializationUtils.serializeBytes(output2, SerializationType.JSON));
                }
                return new ExtensionResult(Collections.singletonMap("hmacGetSecret", results));
            }
        }
    }

    static class LargeBlobExtension extends Extension {

        private static final org.slf4j.Logger logger = LoggerFactory.getLogger(LargeBlobExtension.class);

        @Nullable private Object action = null;
        public LargeBlobExtension(final Ctap2Session ctap) {
            super("largeBlobKey", ctap);
        }

        @Override
        public boolean isSupported() {
            return super.isSupported() && ctap.getCachedInfo().getOptions().containsKey("largeBlobs");
        }

        @Nullable
        @Override
        public CreateInputResult processCreateInput(Map<String, ?> inputs) {
            @SuppressWarnings("unchecked")
            Map<String, Object> data = (Map<String, Object>) inputs.get("largeBlob");
            if (data != null) {
                if (data.containsKey("read") || data.containsKey("write")) {
                    throw new IllegalArgumentException("Invalid set of parameters");
                }
                if ("required".equals(data.get("support")) && !isSupported()) {
                    throw new IllegalArgumentException("Authenticator does not support large" +
                            " blob storage");
                }
                return buildCreateInputResult(true);
            }
            return null;
        }

        @Nullable
        @Override
        public ExtensionResult processGetOutput(
                Ctap2Session.AssertionData assertionData,
                GetOutputParameters parameters) {

            byte[] largeBlobKey = assertionData.getLargeBlobKey();
            if (largeBlobKey == null) {
                return null;
            }

            try {
                if (Boolean.TRUE.equals(action)) {
                    LargeBlobs largeBlobs = new LargeBlobs(ctap);
                    byte[] blob = largeBlobs.getBlob(largeBlobKey);
                    return new ExtensionResult(Collections.singletonMap("largeBlob",
                            blob != null
                                    ? Collections.singletonMap("blob",
                                    serializeBytes(blob, SerializationType.JSON))
                                    : Collections.emptyMap()));
                } else if (action != null && action instanceof byte[]) {
                    byte[] bytes = (byte[]) action;
                    LargeBlobs largeBlobs = new LargeBlobs(
                            ctap,
                            parameters.getPinUvAuthProtocol(),
                            parameters.getAuthToken());
                    largeBlobs.putBlob(largeBlobKey, bytes);

                    return new ExtensionResult(
                            Collections.singletonMap("largeBlob",
                                    Collections.singletonMap("written", true)));
                }
            } catch (IOException | CommandException | GeneralSecurityException e) {
                Logger.error(logger, "LargeBlob processing failed: ", e);
            }

            return null;
        }

        @SuppressWarnings("unchecked")
        @Nullable
        @Override
        public GetInputResult processGetInput(Map<String, ?> inputs) {
            Map<String, Object> data = (Map<String, Object>) inputs.get("largeBlob");
            GetInputResult result = null;
            if (data != null && data.containsKey("read")) {
                action = data.get("read");
                result = buildGetInputResult(Boolean.TRUE, ClientPin.PIN_PERMISSION_NONE);
            } else if (data != null && data.containsKey("write")) {
                action = SerializationUtils.deserializeBytes(
                        data.get("write"),
                        SerializationType.JSON);
                result = buildGetInputResult(Boolean.TRUE, ClientPin.PIN_PERMISSION_LBW);
            }
            return result;
        }

        @Nullable
        @Override
        public ExtensionResult processCreateOutput(AttestationObject attestationObject) {
            return new ExtensionResult(
                    Collections.singletonMap("largeBlob",
                            Collections.singletonMap("supported",
                                    attestationObject.getLargeBlobKey() != null)));
        }
    }

    static class CredBlobExtension extends Extension {
        public CredBlobExtension(final Ctap2Session ctap) {
            super("credBlob", ctap);
        }

        @Nullable
        @Override
        public CreateInputResult processCreateInput(Map<String, ?> inputs) {
            if (isSupported()) {
                String b64Blob = (String) inputs.get("credBlob");
                if (b64Blob != null) {
                    byte[] blob = deserializeBytes(b64Blob, SerializationType.JSON);
                    if (blob.length <= ctap.getCachedInfo().getMaxCredBlobLength()) {
                        return buildCreateInputResult(blob);
                    }
                }
            }
            return null;
        }

        @Nullable
        @Override
        public GetInputResult processGetInput(Map<String, ?> inputs) {
            if (isSupported() && Boolean.TRUE.equals(inputs.get("getCredBlob"))) {
                return buildGetInputResult(true);
            }
            return null;
        }
    }

    static class CredProtectExtension extends Extension {

        static final String OPTIONAL = "userVerificationOptional";
        static final String OPTIONAL_WITH_LIST = "userVerificationOptionalWithCredentialIDList";
        static final String REQUIRED = "userVerificationRequired";

        public CredProtectExtension(final Ctap2Session ctap) {
            super("credProtect", ctap);
        }

        @Nullable
        @Override
        public CreateInputResult processCreateInput(Map<String, ?> inputs) {
            String credentialProtectionPolicy = (String) inputs.get("credentialProtectionPolicy");
            if (credentialProtectionPolicy == null) {
                return null;
            }

            @Nullable Integer credProtect = null;
            switch (credentialProtectionPolicy) {
                case OPTIONAL:
                    credProtect = 0x01;
                    break;
                case OPTIONAL_WITH_LIST:
                    credProtect = 0x02;
                    break;
                case REQUIRED:
                    credProtect = 0x03;
                    break;
            }
            Boolean enforce = (Boolean) inputs.get("enforceCredentialProtectionPolicy");
            if (Boolean.TRUE.equals(enforce) && !isSupported() && credProtect != null && credProtect > 0x01) {
                throw new IllegalArgumentException("Authenticator does not support Credential Protection");
            }

            return credProtect != null
                    ? buildCreateInputResult(credProtect)
                    : null;
        }
    }

    static class MinPinLengthExtension extends Extension {
        public MinPinLengthExtension(final Ctap2Session ctap) {
            super("minPinLength", ctap);
        }

        @Override
        public boolean isSupported() {
            return super.isSupported() && ctap.getCachedInfo().getOptions().containsKey("setMinPINLength");
        }

        @Nullable
        @Override
        public CreateInputResult processCreateInput(Map<String, ?> inputs) {
            if (!isSupported()) {
                return null;
            }
            Boolean input = (Boolean) inputs.get(name);
            if (input == null) {
                return null;
            }
            return buildCreateInputResult(Boolean.TRUE.equals(input));
        }
    }

    static byte[] hash(byte[] message) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(message);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    static public class ExtensionResults {
        final private List<ExtensionResult> extensionResults = new ArrayList<>();

        public void add(ExtensionResult extensionResult) {
            extensionResults.add(extensionResult);
        }

        public Map<String, Object> toMap() {
            Map<String, Object> map = new HashMap<>();
            for (ExtensionResult extensionResult : extensionResults) {
                map.putAll(extensionResult.getResult());
            }
            return map;
        }
    }

    static public class ExtensionResult {
        private final Map<String, Object> result;

        public ExtensionResult(Map<String, Object> result) {
            this.result = result;
        }

        public Map<String, Object> getResult() {
            return result;
        }
    }

    static public class Builder {
        @Nullable
        static public Extension get(String name, final Ctap2Session ctap) {
            switch (name) {
                case "hmac-secret":
                    return new HmacSecretExtension(ctap);
                case "largeBlobKey":
                    return new LargeBlobExtension(ctap);
                case "credBlob":
                    return new CredBlobExtension(ctap);
                case "credProtect":
                    return new CredProtectExtension(ctap);
                case "minPinLength":
                    return new MinPinLengthExtension(ctap);
                case "sign":
                    return new SignExtension(ctap);
            }
            return null;
        }

    }

    static public class CreateInputParameters {
        final PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions;

        public CreateInputParameters(PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions) {
            this.publicKeyCredentialCreationOptions = publicKeyCredentialCreationOptions;
        }

        public PublicKeyCredentialCreationOptions getPublicKeyCredentialCreationOptions() {
            return publicKeyCredentialCreationOptions;
        }
    }

    static public class CreateOutputParameters {
        @Nullable
        final byte[] authToken;
        @Nullable
        final PinUvAuthProtocol pinUvAuthProtocol;

        public CreateOutputParameters(
                @Nullable byte[] authToken,
                @Nullable PinUvAuthProtocol pinUvAuthProtocol) {
            this.authToken = authToken;
            this.pinUvAuthProtocol = pinUvAuthProtocol;
        }
    }

    static public class GetInputParameters {
        final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

        final ClientPin clientPin;

        @Nullable
        final PublicKeyCredentialDescriptor selectedCredential;

        public GetInputParameters(
                PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
                ClientPin clientPin,
                @Nullable
                PublicKeyCredentialDescriptor selectedCredential) {
            this.publicKeyCredentialRequestOptions = publicKeyCredentialRequestOptions;
            this.clientPin = clientPin;
            this.selectedCredential = selectedCredential;
        }

        public PublicKeyCredentialRequestOptions getPublicKeyCredentialRequestOptions() {
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

    static public class GetOutputParameters {
        private final ClientPin clientPin;
        @Nullable
        private final byte[] authToken;
        @Nullable
        private final PinUvAuthProtocol pinUvAuthProtocol;
        public GetOutputParameters(
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

    static public class CreateInputResult {
        private final Map<String, Object> result;
        private final int permissions;

        CreateInputResult(String name, Object data) {
            this(name, data, ClientPin.PIN_PERMISSION_NONE);
        }

        CreateInputResult(String name, Object data, int permissions) {
            this.result = Collections.singletonMap(name, data);

            this.permissions = permissions;
        }

        public Map<String, Object> getResult() {
            return result;
        }

        public int getPermissions() {
            return permissions;
        }
    }

    static public class GetInputResult {
        private final Map<String, Object> result;
        private final int permissions;

        private GetInputResult(String name, Object data) {
            this(name, data, ClientPin.PIN_PERMISSION_NONE);
        }

        private GetInputResult(String name, Object data, int permissions) {
            this.result = Collections.singletonMap(name, data);

            this.permissions = permissions;
        }

        public Map<String, Object> getResult() {
            return result;
        }

        public int getPermissions() {
            return permissions;
        }
    }
}

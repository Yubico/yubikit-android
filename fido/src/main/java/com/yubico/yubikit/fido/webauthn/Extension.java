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

import javax.annotation.Nullable;

public class Extension {

    abstract public static class ExtensionDataProvider {

        @Nullable
        abstract protected Object getByString(String key);

        @Nullable
        final public Object get(String key) {
            return getByString(key);
        }
    }

    static public class ExtensionResults {
        final private List<ExtensionResult> extensionResults = new ArrayList<>();

        public void add(ExtensionResult extensionResult) {
            extensionResults.add(extensionResult);
        }

        public Map<String, Object> toMap(SerializationType serializationType) {
            Map<String, Object> map = new HashMap<>();
            for (ExtensionResult extensionResult : extensionResults) {
                map.putAll(extensionResult.toMap(serializationType));
            }
            return map;
        }
    }

    abstract static public class ExtensionResult {
        public abstract Map<String, Object> toMap(SerializationType serializationType);
    }

    static public class Builder {
        @Nullable
        static public Extension get(String name, final ExtensionDataProvider extensionDataProvider) {
            switch (name) {
                case "hmac-secret":
                    return new HmacSecretExtension(extensionDataProvider);
                case "largeBlobKey":
                    return new LargeBlobExtension(extensionDataProvider);
                case "credBlob":
                    return new CredBlobExtension(extensionDataProvider);
                case "credProtect":
                    return new CredProtectExtension(extensionDataProvider);
                case "minPinLength":
                    return new MinPinLengthExtension(extensionDataProvider);
            }
            return null;
        }

    }

    protected final String name;
    protected final ExtensionDataProvider dataProvider;

    Extension(String name, final ExtensionDataProvider dataProvider) {
        this.dataProvider = dataProvider;
        this.name = name;
    }

    public boolean isSupported() {
        Ctap2Session.InfoData info = (Ctap2Session.InfoData) dataProvider.get("cachedInfo");
        return info != null && info.getExtensions().contains(name);
    }

    @Nullable
    public String getName() {
        return name;
    }

    public int getCreatePermissions() {
        return ClientPin.PIN_PERMISSION_NONE;
    }

    @Nullable
    public Object processCreateInput(Map<String, ?> inputs) {
        return null;
    }

    @Nullable
    public ExtensionResult processCreateOutput(
            AttestationObject attestationObject,
            @Nullable byte[] token,
            @Nullable PinUvAuthProtocol pinUvAuthProtocol) {
        return null;
    }

    @Nullable
    public Object processGetInput(Map<String, ?> inputs) {
        return null;
    }

    public int getGetPermissions() {
        return ClientPin.PIN_PERMISSION_NONE;
    }

    @Nullable
    public ExtensionResult processGetOutput(
            Ctap2Session.AssertionData assertionData,
            @Nullable byte[] pinUvAuthToken,
            @Nullable PinUvAuthProtocol pinUvAuthProtocol) {
        return null;
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

        public HmacSecretExtension(final ExtensionDataProvider dataProvider) {
            super("hmac-secret", dataProvider);
        }

        @Nullable
        @Override
        public Object processCreateInput(Map<String, ?> inputs) {
            if (Boolean.TRUE.equals(inputs.get("hmacCreateSecret"))) {
                prf = false;
                return true;
            } else if (inputs.get("prf") != null) {
                prf = true;
                return true;
            }
            return null;
        }

        @Nullable
        @Override
        public ExtensionResult processCreateOutput(
                AttestationObject attestationObject,
                @Nullable byte[] token,
                @Nullable PinUvAuthProtocol pinUvAuthProtocol) {
            Map<String, ?> extensions = attestationObject.getAuthenticatorData().getExtensions();

            boolean enabled = extensions != null && Boolean.TRUE.equals(extensions.get(name));
            return new ExtensionResult() {
                @Override
                public Map<String, Object> toMap(SerializationType serializationType) {
                    if (prf) {
                        return Collections.singletonMap(
                                "prf",
                                Collections.singletonMap(
                                        "enabled", enabled));
                    } else {
                        return Collections.singletonMap(
                                "hmacCreateSecret", enabled);
                    }
                }
            };
        }

        @SuppressWarnings("unchecked")
        @Nullable
        @Override
        public Object processGetInput(Map<String, ?> inputs) {
            if (!isSupported()) {
                return null;
            }

            Salts salts;
            Map<String, Object> data = (Map<String, Object>) inputs.get("prf");
            if (data != null) {
                Map<String, Object> secrets = (Map<String, Object>) data.get("eval");
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

            final ClientPin clientPin = (ClientPin) dataProvider.get("clientPin");
            if (clientPin == null) {
                throw new IllegalArgumentException("Extension data provider missing clientPin");
            }

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
                return hmacGetSecretInput;
            } catch (IOException | CommandException e) {
                return null;
            }
        }

        @Nullable
        @Override
        public ExtensionResult processGetOutput(
                Ctap2Session.AssertionData assertionData,
                @Nullable byte[] pinUvAuthToken,
                @Nullable PinUvAuthProtocol pinUvAuthProtocol) {

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

            final ClientPin clientPin = (ClientPin) dataProvider.get("clientPin");
            if (clientPin == null) {
                throw new IllegalArgumentException("Extension data provider missing clientPin");
            }

            byte[] decrypted = clientPin.getPinUvAuth().decrypt(sharedSecret, value);

            byte[] output1 = Arrays.copyOf(decrypted, SALT_LEN);
            byte[] output2 = decrypted.length > SALT_LEN
                    ? Arrays.copyOfRange(decrypted, SALT_LEN, 2 * SALT_LEN)
                    : new byte[0];

            Logger.debug(logger, "Decrypted:  {}, o1: {}, o2: {}",
                    StringUtils.bytesToHex(decrypted),
                    StringUtils.bytesToHex(output1),
                    StringUtils.bytesToHex(output2));


            if (prf) {
                return new ExtensionResult() {
                    @Override
                    public Map<String, Object> toMap(SerializationType serializationType) {

                        Map<String, Object> results = new HashMap<>();
                        results.put("first", SerializationUtils.serializeBytes(output1, serializationType));
                        if (output2.length > 0) {
                            results.put("second", SerializationUtils.serializeBytes(output2, serializationType));
                        }

                        return Collections.singletonMap(
                                "prf",
                                Collections.singletonMap("results", results));
                    }
                };
            } else {
                return new ExtensionResult() {
                    @Override
                    public Map<String, Object> toMap(SerializationType serializationType) {
                        Map<String, Object> results = new HashMap<>();
                        results.put("output1", SerializationUtils.serializeBytes(output1, serializationType));
                        if (output2.length > 0) {
                            results.put("output2", SerializationUtils.serializeBytes(output2, serializationType));
                        }

                        return Collections.singletonMap("hmacGetSecret", results);
                    }
                };
            }
        }
    }

    static class LargeBlobExtension extends Extension {

        private static final org.slf4j.Logger logger = LoggerFactory.getLogger(LargeBlobExtension.class);

        @Nullable private Object action = null;
        private int getPermission = ClientPin.PIN_PERMISSION_NONE;

        public LargeBlobExtension(final ExtensionDataProvider dataProvider) {
            super("largeBlobKey", dataProvider);
        }

        @Override
        public boolean isSupported() {
            Ctap2Session.InfoData info = (Ctap2Session.InfoData) dataProvider.get("cachedInfo");
            return super.isSupported() && info != null && info.getOptions().containsKey("largeBlobs");
        }

        @Nullable
        @Override
        public Object processCreateInput(Map<String, ?> inputs) {
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
                return Boolean.TRUE;
            }
            return null;
        }

        @Nullable
        @Override
        public ExtensionResult processGetOutput(
                Ctap2Session.AssertionData assertionData,
                @Nullable byte[] pinUvAuthToken,
                @Nullable PinUvAuthProtocol pinUvAuthProtocol) {

            Ctap2Session ctap = (Ctap2Session) dataProvider.get("ctap");
            if (ctap == null) {
                throw new IllegalArgumentException("Extension data provider missing ctap");
            }

            byte[] largeBlobKey = assertionData.getLargeBlobKey();
            if (largeBlobKey == null) {
                return null;
            }

            try {
                if (Boolean.TRUE.equals(action)) {
                    LargeBlobs largeBlobs = new LargeBlobs(ctap);
                    byte[] blob = largeBlobs.getBlob(largeBlobKey);
                    return new ExtensionResult() {
                        @Override
                        public Map<String, Object> toMap(SerializationType serializationType) {
                            return Collections.singletonMap("largeBlob",
                                    blob != null
                                            ? Collections.singletonMap("blob",
                                            serializeBytes(blob, serializationType))
                                            : Collections.emptyMap());
                        }
                    };
                } else if (action != null && action instanceof byte[]) {
                    byte[] bytes = (byte[]) action;
                    LargeBlobs largeBlobs = new LargeBlobs(ctap, pinUvAuthProtocol, pinUvAuthToken);
                    largeBlobs.putBlob(largeBlobKey, bytes);

                    return new ExtensionResult() {
                        @Override
                        public Map<String, Object> toMap(SerializationType serializationType) {
                            return Collections.singletonMap(
                                    "largeBlob",
                                    Collections.singletonMap(
                                            "written",
                                            true));
                        }
                    };
                }
            } catch (IOException | CommandException | GeneralSecurityException e) {
                Logger.error(logger, "LargeBlob processing failed: ", e);
            }

            return null;
        }

        @Override
        public int getGetPermissions() {
            return getPermission;
        }

        @SuppressWarnings("unchecked")
        @Nullable
        @Override
        public Object processGetInput(Map<String, ?> inputs) {
            Map<String, Object> data = (Map<String, Object>) inputs.get("largeBlob");
            Boolean result = null;
            if (data != null && data.containsKey("read")) {
                action = data.get("read");
                getPermission = ClientPin.PIN_PERMISSION_NONE;
                result = Boolean.TRUE;
            } else if (data != null && data.containsKey("write")) {
                action = SerializationUtils.deserializeBytes(
                        data.get("write"),
                        SerializationType.JSON);
                getPermission = ClientPin.PIN_PERMISSION_LBW;
                result = Boolean.TRUE;
            }
            return result;
        }

        @Nullable
        @Override
        public ExtensionResult processCreateOutput(AttestationObject attestationObject, @Nullable byte[] token, @Nullable PinUvAuthProtocol pinUvAuthProtocol) {
            return new ExtensionResult() {
                @Override
                public Map<String, Object> toMap(SerializationType serializationType) {
                    return Collections.singletonMap("largeBlob", Collections.singletonMap("supported", attestationObject.getLargeBlobKey() != null));
                }
            };
        }
    }

    static class CredBlobExtension extends Extension {
        public CredBlobExtension(final ExtensionDataProvider dataProvider) {
            super("credBlob", dataProvider);
        }

        @Nullable
        @Override
        public Object processCreateInput(Map<String, ?> inputs) {
            if (isSupported()) {
                String b64Blob = (String) inputs.get("credBlob");
                if (b64Blob != null) {
                    byte[] blob = deserializeBytes(b64Blob, SerializationType.JSON);
                    Ctap2Session.InfoData cachedInfo = (Ctap2Session.InfoData) dataProvider.get("cachedInfo");
                    if (blob.length <= (cachedInfo == null ? 0 : cachedInfo.getMaxCredBlobLength())) {
                        return blob;
                    }
                }
            }
            return null;
        }

        @Nullable
        @Override
        public Object processGetInput(Map<String, ?> inputs) {
            if (isSupported() && Boolean.TRUE.equals(inputs.get("getCredBlob"))) {
                return true;
            }
            return null;
        }
    }

    static class CredProtectExtension extends Extension {

        static final String OPTIONAL = "userVerificationOptional";
        static final String OPTIONAL_WITH_LIST = "userVerificationOptionalWithCredentialIDList";
        static final String REQUIRED = "userVerificationRequired";

        public CredProtectExtension(final ExtensionDataProvider dataProvider) {
            super("credProtect", dataProvider);
        }

        @Nullable
        @Override
        public Object processCreateInput(Map<String, ?> inputs) {
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

            return credProtect;
        }
    }

    static class MinPinLengthExtension extends Extension {
        public MinPinLengthExtension(final ExtensionDataProvider dataProvider) {
            super("minPinLength", dataProvider);
        }

        @Override
        public boolean isSupported() {
            Ctap2Session.InfoData cachedInfo = (Ctap2Session.InfoData) dataProvider.get("cachedInfo");
            return super.isSupported() && cachedInfo != null && cachedInfo.getOptions()
                    .containsKey("setMinPINLength");
        }

        @Nullable
        @Override
        public Object processCreateInput(Map<String, ?> inputs) {

            if (!isSupported()) {
                return null;
            }
            Boolean input = (Boolean) inputs.get(name);
            if (input == null) {
                return null;
            }
            return Boolean.TRUE.equals(input);
        }
    }

    static byte[] hash(byte[] message) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(message);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}

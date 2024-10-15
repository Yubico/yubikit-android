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
        static public Extension get(String name, Ctap2Session ctap, PinUvAuthProtocol pinUvAuthProtocol) {
            switch (name) {
                case "hmac-secret":
                    return new HmacSecretExtension(ctap, pinUvAuthProtocol);
                case "largeBlobKey":
                    return new LargeBlobExtension(ctap, pinUvAuthProtocol);
                case "credBlob":
                    return new CredBlobExtension(ctap, pinUvAuthProtocol);
                case "credProtect":
                    return new CredProtectExtension(ctap, pinUvAuthProtocol);
                case "minPinLength":
                    return new MinPinLengthExtension(ctap, pinUvAuthProtocol);
            }
            return null;
        }

    }

    // helper types
    static public class InputWithPermission {
        @Nullable public final Object input;
        public final int permissions;

        InputWithPermission(@Nullable Object input, int permissions) {
            this.input = input;
            this.permissions = permissions;
        }
    }


    protected final String name;
    protected final Ctap2Session ctap;
    protected final PinUvAuthProtocol pinUvAuthProtocol;

    Extension(Ctap2Session ctap, PinUvAuthProtocol pinUvAuthProtocol, String name) {
        this.ctap = ctap;
        this.pinUvAuthProtocol = pinUvAuthProtocol;
        this.name = name;
    }

    public boolean isSupported() {
        return ctap.getCachedInfo().getExtensions().contains(name);
    }

    @Nullable
    public String getName() {
        return name;
    }

    @Nullable
    public Object processCreateInput(Map<String, ?> inputs) {
        return null;
    }

    public InputWithPermission processCreateInputWithPermissions(Map<String, ?> inputs) {
        return new InputWithPermission(processCreateInput(inputs), ClientPin.PIN_PERMISSION_NONE);
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

    public InputWithPermission processGetInputWithPermissions(Map<String, ?> inputs) {
        return new InputWithPermission(processGetInput(inputs), ClientPin.PIN_PERMISSION_NONE);
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

        private byte[] prfSalt(byte[] secret) {
            return hash(ByteBuffer
                    .allocate(13 + secret.length)
                    .put("WebAuthn PRF".getBytes(StandardCharsets.US_ASCII))
                    .put((byte) 0x00)
                    .put(secret)
                    .array());
        }

        public HmacSecretExtension(Ctap2Session ctap, PinUvAuthProtocol pinUvAuthProtocol) {
            super(ctap, pinUvAuthProtocol, "hmac-secret");
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

                byte[] first = SerializationUtils.deserializeBytes(
                        Objects.requireNonNull((String) secrets.get("first")),
                        SerializationType.JSON);

                byte[] second = secrets.containsKey("second")
                        ? prfSalt(
                        SerializationUtils.deserializeBytes(
                                secrets.get("second"),
                                SerializationType.JSON
                        ))
                        : null;

                salts = new Salts(prfSalt(first), second);

                Logger.debug(logger, "Inputs: {}, {}", secrets.get("first"), secrets.get("second"));
                Logger.debug(logger, "Salts: {}, {}", StringUtils.bytesToHex(salts.salt1), StringUtils.bytesToHex(salts.salt2));

                prf = true;
            } else {
                data = (Map<String, Object>) inputs.get("hmacGetSecret");
                if (data == null) {
                    return null;
                }
                salts = new Salts(prfSalt(Objects.requireNonNull((byte[]) data.get("salt1"))),
                        data.containsKey("salt2")
                                ? prfSalt(Objects.requireNonNull((byte[]) data.get("salt2")))
                                : null);
                prf = false;
            }

            if (!(salts.salt1.length == SALT_LEN &&
                    (salts.salt2.length == 0 || salts.salt2.length == SALT_LEN))) {
                throw new IllegalArgumentException("Invalid salt length");
            }

            final ClientPin clientPin = new ClientPin(ctap, pinUvAuthProtocol);
            try {
                Pair<Map<Integer, ?>, byte[]> keyAgreemenbt = clientPin.getSharedSecret();

                this.sharedSecret = keyAgreemenbt.second;

                byte[] saltEnc = pinUvAuthProtocol.encrypt(
                        sharedSecret,
                        ByteBuffer
                                .allocate(salts.salt1.length + salts.salt2.length)
                                .put(salts.salt1)
                                .put(salts.salt2)
                                .array());

                byte[] saltAuth = pinUvAuthProtocol.authenticate(
                        keyAgreemenbt.second,
                        saltEnc);

                final Map<Integer, Object> hmacGetSecretInput = new HashMap<>();
                hmacGetSecretInput.put(1, keyAgreemenbt.first);
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

            byte[] decrypted = this.pinUvAuthProtocol.decrypt(sharedSecret, value);

            byte[] output1 = Arrays.copyOf(decrypted, SALT_LEN);
            byte[] output2 = Arrays.copyOfRange(decrypted, SALT_LEN, 2 * SALT_LEN);

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

        public LargeBlobExtension(Ctap2Session ctap, PinUvAuthProtocol pinUvAuthProtocol) {
            super(ctap, pinUvAuthProtocol, "largeBlobKey");
        }

        @Override
        public boolean isSupported() {
            return super.isSupported() && ctap.getCachedInfo().getOptions()
                    .containsKey("largeBlobs");
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
        public InputWithPermission processGetInputWithPermissions(Map<String, ?> inputs) {
            @SuppressWarnings("unchecked")
            Map<String, Object> data = inputs.containsKey("largeBlob")
                    ? (Map<String, Object>) processGetInput((Map<String, Object>) inputs.get("largeBlob"))
                    : Collections.emptyMap();

            int permissions = ClientPin.PIN_PERMISSION_NONE;

            if (data == null) {
                return new InputWithPermission(null, permissions);
            }

            if (data.containsKey("support") || (data.containsKey("read") && data.containsKey("write"))) {
                throw new IllegalArgumentException("Invalid set of parameters");
            }

            if (!isSupported()) {
                throw new IllegalArgumentException("Authenticator does not support large blob storage");
            }

            if (data.containsKey("read")) {
                action = Boolean.TRUE;
            } else {
                action = data.get("write");
                permissions = ClientPin.PIN_PERMISSION_LBW; // Large Blob Write permission
            }

            return new InputWithPermission(data.isEmpty() ? null : Boolean.TRUE, permissions);
        }

        @Nullable
        @Override
        public Object processGetInput(Map<String, ?> inputs) {
            Map<String, Object> result = new HashMap<>();
            if (inputs.containsKey("read")) {
                result.put("read", inputs.get("read"));
            }
            if (inputs.containsKey("write")) {
                result.put("write", SerializationUtils.deserializeBytes(inputs.get("write"), SerializationType.JSON));
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
        public CredBlobExtension(Ctap2Session ctap, PinUvAuthProtocol pinUvAuthProtocol) {
            super(ctap, pinUvAuthProtocol, "credBlob");
        }

        @Nullable
        @Override
        public Object processCreateInput(Map<String, ?> inputs) {
            if (isSupported()) {
                byte[] blob = (byte[]) inputs.get("credBlob");
                if (blob != null && blob.length <= ctap.getCachedInfo().getMaxCredBlobLength()) {
                    return blob;
                }
            }

            return null;
        }

        @Nullable
        @Override
        public Object processGetInput(Map<String, ?> inputs) {
            return super.processGetInput(inputs);
        }
    }

    static class CredProtectExtension extends Extension {

        static final String OPTIONAL = "userVerificationOptional";
        static final String OPTIONAL_WITH_LIST = "userVerificationOptionalWithCredentialIDList";
        static final String REQUIRED = "userVerificationRequired";

        public CredProtectExtension(Ctap2Session ctap, PinUvAuthProtocol pinUvAuthProtocol) {
            super(ctap, pinUvAuthProtocol, "credProtect");
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
        public MinPinLengthExtension(Ctap2Session ctap, PinUvAuthProtocol pinUvAuthProtocol) {
            super(ctap, pinUvAuthProtocol, "minPinLength");
        }

        @Override
        public boolean isSupported() {
            return super.isSupported() && ctap.getCachedInfo().getOptions()
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

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
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import com.yubico.yubikit.fido.webauthn.SerializationUtils;
import com.yubico.yubikit.fido.webauthn.ext.LargeBlobs;

import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
        static public Extension get(String name, Ctap2Session session) {
            switch (name) {
                case "hmac-secret":
                    return new HmacSecretExtension(session);
                case "largeBlobKey":
                    return new LargeBlobExtension(session);
                case "credBlob":
                    return new CredBlobExtension(session);
                case "credProtect":
                    return new CredProtectExtension(session);
                case "minPinLength":
                    return new MinPinLengthExtension(session);
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
    protected final Ctap2Session session;

    Extension(Ctap2Session session, String name) {
        this.session = session;
        this.name = name;
    }

    public boolean isSupported() {
        return session.getCachedInfo().getExtensions().contains(name);
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
        public HmacSecretExtension(Ctap2Session session) {
            super(session, "hmac-secret");
        }
    }

    static class LargeBlobExtension extends Extension {

        private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Extension.class);

        @Nullable private Object action = null;

        public LargeBlobExtension(Ctap2Session session) {
            super(session, "largeBlobKey");
        }

        @Override
        public boolean isSupported() {
            return super.isSupported() && session.getCachedInfo().getOptions()
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
                    LargeBlobs largeBlobs = new LargeBlobs(session);
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
                    LargeBlobs largeBlobs = new LargeBlobs(session, pinUvAuthProtocol, pinUvAuthToken);
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
        public CredBlobExtension(Ctap2Session session) {
            super(session, "credBlob");
        }

        @Nullable
        @Override
        public Object processCreateInput(Map<String, ?> inputs) {
            if (isSupported()) {
                byte[] blob = (byte[]) inputs.get("credBlob");
                if (blob != null && blob.length <= session.getCachedInfo().getMaxCredBlobLength()) {
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

        public CredProtectExtension(Ctap2Session session) {
            super(session, "credProtect");
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
        public MinPinLengthExtension(Ctap2Session session) {
            super(session, "minPinLength");
        }

        @Override
        public boolean isSupported() {
            return super.isSupported() && session.getCachedInfo().getOptions()
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
}

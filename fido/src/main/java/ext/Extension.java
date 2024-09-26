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

package ext;

import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAssertionResponse;

import java.util.Map;

import javax.annotation.Nullable;

public class Extension {

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
        @Nullable
        public final Object input;
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
    public Map<String, Object> processCreateOutput(
            AttestationObject attestationObject,
            @Nullable byte[] token,
            @Nullable PinUvAuthProtocol pinUvAuthProtocol
    ) {
        return null;
    }

    @Nullable
    public Object processGetInput(Map<String, Object> inputs) {
        return null;
    }

    public InputWithPermission processGetInputWithPermissions(Map<String, Object> inputs) {
        return new InputWithPermission(processGetInput(inputs), ClientPin.PIN_PERMISSION_NONE);
    }

    @Nullable
    public Map<String, Object> processGetOutput(
            AuthenticatorAssertionResponse assertionResponse,
            @Nullable String token,
            @Nullable PinUvAuthProtocol pinUvAuthProtocol
    ) {
        return null;
    }


    static class HmacSecretExtension extends Extension {
        public HmacSecretExtension(Ctap2Session session) {
            super(session, "hmac-secret");
        }
    }

    static class LargeBlobExtension extends Extension {
        public LargeBlobExtension(Ctap2Session session) {
            super(session, "largeBlobKey");
        }
    }

    static class CredBlobExtension extends Extension {
        public CredBlobExtension(Ctap2Session session) {
            super(session, "credBlob");
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


            @Nullable
            Integer credProtect = null;
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
            return session.getCachedInfo().getOptions().containsKey("setMinPINLength");
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

/*
 * Copyright (C) 2020-2023 Yubico.
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

package com.yubico.yubikit.fido.client;

import static com.yubico.yubikit.fido.webauthn.AttestationObject.KEY_ATTESTATION_STATEMENT;
import static com.yubico.yubikit.fido.webauthn.AttestationObject.KEY_AUTHENTICATOR_DATA;
import static com.yubico.yubikit.fido.webauthn.AttestationObject.KEY_FORMAT;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import com.yubico.yubikit.fido.webauthn.UserVerificationRequirement;

import java.io.Closeable;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;

/**
 * A "basic" WebAuthn client implementation which wraps a YubiKeySession.
 * <p>
 * Provides the following functionality:
 * <ul>
 * <li>MakeCredential: Registers a new credential. If a PIN is needed, it is passed to this method.</li>
 * <li>GetAssertion: Authenticate an existing credential. If a PIN is needed, it is passed to this method.</li>
 * <li>PIN Management: Set or change the PIN code of an Authenticator, or see its state.</li>
 * <li>Credential Management: List or delete resident credentials of an Authenticator.</li>
 * </ul>
 * The timeout parameter in the request options is ignored. To cancel a request pass a {@link CommandState}
 * instance to the call and use its cancel method.
 * <p>
 * No support for Extensions. Any Extensions provided will be ignored.
 */
public class BasicWebAuthnClient implements Closeable {
    private static final String OPTION_CLIENT_PIN = "clientPin";
    private static final String OPTION_CREDENTIAL_MANAGEMENT = "credentialMgmtPreview";
    private static final String OPTION_USER_VERIFICATION = "uv";
    private static final String OPTION_RESIDENT_KEY = "rk";

    private final Ctap2Session ctap;
    private final Ctap2Session.InfoData info;

    private final boolean pinSupported;
    private final boolean uvSupported;

    private final ClientPin clientPin;

    private boolean pinConfigured;
    private boolean uvConfigured;

    final private boolean credentialManagementSupported;

    public BasicWebAuthnClient(Ctap2Session session) throws IOException, CommandException {
        this.ctap = session;
        this.info = ctap.getInfo();

        Map<String, ?> options = info.getOptions();

        Boolean clientPin = (Boolean) options.get(OPTION_CLIENT_PIN);
        pinSupported = clientPin != null;
        //TODO: Add support for other PIN protocols when needed.
        if (pinSupported && info.getPinUvAuthProtocols().contains(PinUvAuthProtocolV1.VERSION)) {
            this.clientPin = new ClientPin(ctap, new PinUvAuthProtocolV1());
        } else {
            this.clientPin = null;
        }
        pinConfigured = pinSupported && clientPin;

        Boolean uv = (Boolean) options.get(OPTION_USER_VERIFICATION);
        uvSupported = uv != null;
        uvConfigured = uvSupported && uv;

        credentialManagementSupported = Boolean.TRUE.equals(options.get(OPTION_CREDENTIAL_MANAGEMENT));
    }

    public Ctap2Session.InfoData getSessionInfoData() {
        return info;
    }

    @Override
    public void close() throws IOException {
        ctap.close();
    }

    /**
     * Create a new WebAuthn credential.
     * <p>
     * PIN is always required if a PIN is configured.
     *
     * @param clientDataHash  Hash of client data.
     * @param options         The options for creating the credential.
     * @param effectiveDomain The effective domain for the request, which is used to validate the RP ID against.
     * @param pin             If needed, the PIN to authorize the credential creation.
     * @param state           If needed, the state to provide control over the ongoing operation
     * @return A WebAuthn public key credential.
     * @throws IOException      A communication error in the transport layer
     * @throws CommandException A communication in the protocol layer
     * @throws ClientError      A higher level error
     */
    @SuppressWarnings("unchecked")
    public Ctap2Session.CredentialData ctapMakeCredential(
            byte[] clientDataHash,
            PublicKeyCredentialCreationOptions options,
            String effectiveDomain,
            @Nullable char[] pin,
            @Nullable CommandState state
    ) throws IOException, CommandException, ClientError {

        if (options.getExtensions() != null) {
            throw new ClientError(ClientError.Code.CONFIGURATION_UNSUPPORTED, "Extensions not supported");
        }

        Map<String, ?> rp = options.getRp().toMap();
        String rpId = options.getRp().getId();
        if (rpId == null) {
            ((Map<String, Object>) rp).put("id", effectiveDomain);
        } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
            throw new ClientError(ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
        }

        byte[] pinUvAuthParam = null;
        int pinUvAuthProtocol = 0;

        Map<String, Boolean> ctapOptions = new HashMap<>();
        AuthenticatorSelectionCriteria authenticatorSelection = options.getAuthenticatorSelection();
        if (authenticatorSelection != null) {
            String residentKeyRequirement = authenticatorSelection.getResidentKey();
            if (ResidentKeyRequirement.REQUIRED.equals(residentKeyRequirement) ||
                    (ResidentKeyRequirement.PREFERRED.equals(residentKeyRequirement) && uvSupported)) {
                ctapOptions.put(OPTION_RESIDENT_KEY, true);
            }
            if (getCtapUv(authenticatorSelection.getUserVerification(), pin != null)) {
                ctapOptions.put(OPTION_USER_VERIFICATION, true);
            }
        } else {
            if (getCtapUv(UserVerificationRequirement.PREFERRED, pin != null)) {
                ctapOptions.put(OPTION_USER_VERIFICATION, true);
            }
        }

        if (pin != null) {
            byte[] pinToken = clientPin.getPinToken(pin);
            pinUvAuthParam = clientPin.getPinUvAuth().authenticate(pinToken, clientDataHash);
            pinUvAuthProtocol = clientPin.getPinUvAuth().getVersion();
        } else if (pinConfigured && !ctapOptions.containsKey(OPTION_USER_VERIFICATION)) {
            throw new PinRequiredClientError();
        }

        final List<PublicKeyCredentialDescriptor> excludeCredentials = removeUnsupportedCredentials(
                options.getExcludeCredentials()
        );

        final Map<String, Object> user = ConversionUtils.publicKeyCredentialUserEntityToMap(options.getUser());

        List<Map<String, ?>> pubKeyCredParams = new ArrayList<>();
        for (PublicKeyCredentialParameters param : options.getPubKeyCredParams()) {
            if (isPublicKeyCredentialTypeSupported(param.getType())) {
                pubKeyCredParams.add(param.toMap());
            }
        }

        return ctap.makeCredential(
                clientDataHash,
                rp,
                user,
                pubKeyCredParams,
                getCredentialList(excludeCredentials),
                null,
                ctapOptions.isEmpty() ? null : ctapOptions,
                pinUvAuthParam,
                pinUvAuthProtocol,
                state
        );
    }

    /**
     * Create a new WebAuthn credential.
     * <p>
     * PIN is always required if a PIN is configured.
     *
     * @param clientDataJson  The UTF-8 encoded ClientData JSON object.
     * @param options         The options for creating the credential.
     * @param effectiveDomain The effective domain for the request, which is used to validate the RP ID against.
     * @param pin             If needed, the PIN to authorize the credential creation.
     * @param state           If needed, the state to provide control over the ongoing operation
     * @return A WebAuthn public key credential.
     * @throws IOException      A communication error in the transport layer
     * @throws CommandException A communication in the protocol layer
     * @throws ClientError      A higher level error
     */
    public PublicKeyCredential makeCredential(
            byte[] clientDataJson,
            PublicKeyCredentialCreationOptions options,
            String effectiveDomain,
            @Nullable char[] pin,
            @Nullable CommandState state
    ) throws IOException, CommandException, ClientError {
        byte[] clientDataHash = hash(clientDataJson);

        try {
            Ctap2Session.CredentialData credential = ctapMakeCredential(
                    clientDataHash,
                    options,
                    effectiveDomain,
                    pin,
                    state
            );

            byte[] authenticatorData = credential.getAuthenticatorData();
            Map<String, Object> attestationObject = new HashMap<>();
            attestationObject.put(KEY_FORMAT, credential.getFormat());
            attestationObject.put(KEY_AUTHENTICATOR_DATA, authenticatorData);
            attestationObject.put(KEY_ATTESTATION_STATEMENT, credential.getAttestationStatement());

            int credentialIdLength = authenticatorData[54];
            byte[] credentialId = Arrays.copyOfRange(authenticatorData, 55, 55 + credentialIdLength);

            return new PublicKeyCredential(
                    credentialId,
                    new AuthenticatorAttestationResponse(
                            clientDataJson,
                            info.getTransports(),
                            Cbor.encode(attestationObject)
                    )
            );
        } catch (CtapException e) {
            if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
                throw new PinInvalidClientError(e, clientPin.getPinRetries());
            }
            throw ClientError.wrapCtapException(e);
        }
    }

    /**
     * Authenticate an existing WebAuthn credential.
     * PIN is required if UV is "required", or if UV is "preferred" and a PIN is configured.
     * If no allowCredentials list is provided (which is the case for a passwordless flow) the Authenticator may contain multiple discoverable credentials for the given RP.
     * In such cases MultipleAssertionsAvailable will be thrown, and can be handled to select an assertion.
     *
     * @param clientDataHash  Hash of client data.
     * @param options         The options for authenticating the credential.
     * @param effectiveDomain The effective domain for the request, which is used to validate the RP ID against.
     * @param pin             If needed, the PIN to authorize the credential creation.
     * @param state           If needed, the state to provide control over the ongoing operation
     * @return Webauthn public key credential with assertion response data.
     * @throws MultipleAssertionsAvailable In case of multiple assertions, catch this to make a selection and get the result.
     * @throws IOException                 A communication error in the transport layer
     * @throws CommandException            A communication in the protocol layer
     * @throws ClientError                 A higher level error
     */
    public Ctap2Session.AssertionData ctapGetAssertion(
            byte[] clientDataHash,
            PublicKeyCredentialRequestOptions options,
            String effectiveDomain,
            @Nullable char[] pin,
            @Nullable CommandState state
    ) throws MultipleAssertionsAvailable, IOException, CommandException, ClientError {
        String rpId = options.getRpId();
        if (rpId == null) {
            rpId = effectiveDomain;
        } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
            throw new ClientError(ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
        }
        Map<String, Boolean> ctapOptions = new HashMap<>();
        if (getCtapUv(options.getUserVerification(), pin != null)) {
            ctapOptions.put(OPTION_USER_VERIFICATION, true);
        }

        if (options.getExtensions() != null) {
            throw new ClientError(ClientError.Code.CONFIGURATION_UNSUPPORTED, "Extensions not supported");
        }

        byte[] pinUvAuthParam = null;
        int pinUvAuthProtocol = 0;
        try {
            if (pin != null) {
                byte[] pinToken = clientPin.getPinToken(pin);
                pinUvAuthParam = clientPin.getPinUvAuth().authenticate(pinToken, clientDataHash);
                pinUvAuthProtocol = clientPin.getPinUvAuth().getVersion();
            }

            final List<PublicKeyCredentialDescriptor> allowCredentials = removeUnsupportedCredentials(
                    options.getAllowCredentials()
            );

            List<Ctap2Session.AssertionData> assertions = ctap.getAssertions(
                    rpId,
                    clientDataHash,
                    getCredentialList(allowCredentials),
                    null,
                    ctapOptions.isEmpty() ? null : ctapOptions,
                    pinUvAuthParam,
                    pinUvAuthProtocol,
                    state
            );
            if (assertions.size() == 1) {
                return assertions.get(0);
            } else {
                throw new MultipleAssertionsAvailable(assertions);
            }
        } catch (CtapException e) {
            if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
                throw new PinInvalidClientError(e, clientPin.getPinRetries());
            }
            throw ClientError.wrapCtapException(e);
        }
    }
    /**
     * Authenticate an existing WebAuthn credential.
     * PIN is required if UV is "required", or if UV is "preferred" and a PIN is configured.
     * If no allowCredentials list is provided (which is the case for a passwordless flow) the Authenticator may contain multiple discoverable credentials for the given RP.
     * In such cases MultipleAssertionsAvailable will be thrown, and can be handled to select an assertion.
     *
     * @param clientDataJson  The UTF-8 encoded ClientData JSON object.
     * @param options         The options for authenticating the credential.
     * @param effectiveDomain The effective domain for the request, which is used to validate the RP ID against.
     * @param pin             If needed, the PIN to authorize the credential creation.
     * @param state           If needed, the state to provide control over the ongoing operation
     * @return Webauthn public key credential with assertion response data.
     * @throws MultipleAssertionsAvailable In case of multiple assertions, catch this to make a selection and get the result.
     * @throws IOException                 A communication error in the transport layer
     * @throws CommandException            A communication in the protocol layer
     * @throws ClientError                 A higher level error
     */
    public PublicKeyCredential getAssertion(
            byte[] clientDataJson,
            PublicKeyCredentialRequestOptions options,
            String effectiveDomain,
            @Nullable char[] pin,
            @Nullable CommandState state
    ) throws MultipleAssertionsAvailable, IOException, CommandException, ClientError {
        byte[] clientDataHash = hash(clientDataJson);

        try {
            Ctap2Session.AssertionData assertion = ctapGetAssertion(
                    clientDataHash,
                    options,
                    effectiveDomain,
                    pin,
                    state
            );

            final List<PublicKeyCredentialDescriptor> allowCredentials = removeUnsupportedCredentials(
                    options.getAllowCredentials()
            );
            return PublicKeyCredential.fromAssertion(assertion, clientDataJson, allowCredentials);
        } catch (CtapException e) {
            if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
                throw new PinInvalidClientError(e, clientPin.getPinRetries());
            }
            throw ClientError.wrapCtapException(e);
        }
    }

    /**
     * Check if the Authenticator supports external PIN.
     *
     * @return If PIN is supported.
     */
    public boolean isPinSupported() {
        return pinSupported;
    }

    /**
     * Check if the Authenticator has been configured with a PIN.
     *
     * @return If a PIN is configured.
     */
    public boolean isPinConfigured() {
        return pinConfigured;
    }

    /**
     * Set the PIN for an Authenticator which supports PIN, but doesn't have one configured.
     *
     * @param pin The PIN to set.
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @throws ClientError      A higher level error.
     */
    public void setPin(char[] pin) throws IOException, CommandException, ClientError {
        if (!pinSupported) {
            throw new ClientError(ClientError.Code.BAD_REQUEST, "PIN is not supported on this device");
        }
        if (pinConfigured) {
            throw new ClientError(ClientError.Code.BAD_REQUEST, "A PIN is already configured on this device");
        }
        try {
            clientPin.setPin(pin);
            pinConfigured = true;
        } catch (CtapException e) {
            throw ClientError.wrapCtapException(e);
        }
    }

    /**
     * Change the PIN for an Authenticator which already has a PIN configured.
     *
     * @param currentPin The current PIN, to authorize the action.
     * @param newPin     The new PIN to set.
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @throws ClientError      A higher level error.
     */
    public void changePin(char[] currentPin, char[] newPin) throws IOException, CommandException, ClientError {
        if (!pinSupported) {
            throw new ClientError(ClientError.Code.BAD_REQUEST, "PIN is not supported on this device");
        }
        if (!pinConfigured) {
            throw new ClientError(ClientError.Code.BAD_REQUEST, "No PIN currently configured on this device");
        }
        try {
            clientPin.changePin(currentPin, newPin);
        } catch (CtapException e) {
            throw ClientError.wrapCtapException(e);
        }
    }

    /**
     * Return an object that provides management of resident key type credentials stored on a YubiKey
     *
     * @param pin The configured PIN
     * @return Credential manager
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @throws ClientError      A higher level error.
     */
    public CredentialManager getCredentialManager(char[] pin) throws IOException, CommandException, ClientError {
        if (!credentialManagementSupported) {
            throw new ClientError(ClientError.Code.CONFIGURATION_UNSUPPORTED, "Credential management is not supported on this device");
        }
        if (!pinConfigured) {
            throw new ClientError(ClientError.Code.BAD_REQUEST, "No PIN currently configured on this device");
        }
        try {
            return new CredentialManager(new CredentialManagement(ctap, clientPin.getPinUvAuth(), clientPin.getPinToken(pin)));
        } catch (CtapException e) {
            throw ClientError.wrapCtapException(e);
        }
    }

    /*
     * Calculates what the CTAP "uv" option should be based on the configuration of the authenticator,
     * the UserVerification parameter to the request, and whether or not a PIN was provided.
     */
    private boolean getCtapUv(String userVerification, boolean pinProvided) throws ClientError {
        if (pinProvided) {
            if (!pinConfigured) {
                throw new ClientError(ClientError.Code.BAD_REQUEST, "PIN provided but not configured");
            }
            // If a PIN was provided this will satisfy the UserVerification requirement regardless of what it is, without requiring uv.
            return false;
        }

        boolean pinUvSupported = pinSupported || uvSupported;

        // No PIN provided
        switch (userVerification) {
            case UserVerificationRequirement.DISCOURAGED:
                // Discouraged, uv = false.
                return false;
            default:
            case UserVerificationRequirement.PREFERRED:
                if (!pinUvSupported) {
                    // No Authenticator support, uv = false
                    return false;
                }
                //Fall through to REQUIRED since we have support for either PIN or uv.
            case UserVerificationRequirement.REQUIRED:
                if (!uvConfigured) {
                    // Can't satisfy UserVerification, fail.
                    if (pinConfigured) {
                        throw new PinRequiredClientError();
                    } else {
                        if (pinUvSupported) {
                            throw new ClientError(ClientError.Code.BAD_REQUEST, "User verification not configured");
                        }
                        throw new ClientError(ClientError.Code.CONFIGURATION_UNSUPPORTED, "User verification not supported");
                    }
                }
                // uv is configured, uv = true.
                return true;
        }
    }

    private static boolean isPublicKeyCredentialTypeSupported(String type) {
        return PublicKeyCredentialType.PUBLIC_KEY.equals(type);
    }

    /**
     * @return new list containing only descriptors with valid {@code PublicKeyCredentialType} type
     */
    @Nullable
    public static List<PublicKeyCredentialDescriptor> removeUnsupportedCredentials(
            @Nullable List<PublicKeyCredentialDescriptor> descriptors
    ) {
        if (descriptors == null || descriptors.isEmpty()) {
            return descriptors;
        }

        final List<PublicKeyCredentialDescriptor> list = new ArrayList<>();
        for (PublicKeyCredentialDescriptor credential : descriptors) {
            if (isPublicKeyCredentialTypeSupported(credential.getType())) {
                list.add(credential);
            }
        }
        return list;
    }

    /**
     * @return new list of Credential descriptors for CBOR serialization.
     */
    @Nullable
    private static List<Map<String, ?>> getCredentialList(@Nullable List<PublicKeyCredentialDescriptor> descriptors) {
        if (descriptors == null || descriptors.isEmpty()) {
            return null;
        }
        List<Map<String, ?>> list = new ArrayList<>();
        for (PublicKeyCredentialDescriptor credential : descriptors) {
            list.add(ConversionUtils.publicKeyCredentialDescriptorToMap(credential));
        }
        return list;
    }

    /**
     * Return SHA-256 hash of the provided input
     *
     * @param message The hash input
     * @return SHA-256 of the input
     */
    static byte[] hash(byte[] message) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(message);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

}

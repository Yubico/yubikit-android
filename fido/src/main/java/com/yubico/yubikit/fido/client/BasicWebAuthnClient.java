/*
 * Copyright (C) 2020-2024 Yubico.
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

import static com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType.PUBLIC_KEY;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.client.extensions.Extensions;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.client.extensions.Extension;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthDummyProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.fido.webauthn.AttestationConveyancePreference;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import com.yubico.yubikit.fido.webauthn.UserVerificationRequirement;

import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

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
@SuppressWarnings("unused")
public class BasicWebAuthnClient implements Closeable {
    private static final String OPTION_CLIENT_PIN = "clientPin";
    private static final String OPTION_USER_VERIFICATION = "uv";
    private static final String OPTION_RESIDENT_KEY = "rk";
    private static final String OPTION_EP = "ep";

    private final UserAgentConfiguration userAgentConfiguration = new UserAgentConfiguration();

    private final Ctap2Session ctap;

    private final boolean pinSupported;
    private final boolean uvSupported;

    private final ClientPin clientPin;

    private boolean pinConfigured;
    private final boolean uvConfigured;

    final private boolean enterpriseAttestationSupported;

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(BasicWebAuthnClient.class);

    public static class UserAgentConfiguration {
        private List<String> epSupportedRpIds = new ArrayList<>();

        public void setEpSupportedRpIds(List<String> epSupportedRpIds) {
            this.epSupportedRpIds = epSupportedRpIds;
        }

        boolean supportsEpForRpId(@Nullable String rpId) {
            return epSupportedRpIds.contains(rpId);
        }
    }

    private static class AuthParams {
        @Nullable
        private final byte[] pinToken;
        @Nullable
        private final PinUvAuthProtocol pinUvAuthProtocol;
        @Nullable
        private final byte[] pinUvAuthParam;

        AuthParams(
                @Nullable byte[] pinToken,
                @Nullable PinUvAuthProtocol pinUvAuthProtocol,
                @Nullable byte[] pinUvAuthParam) {
            this.pinToken = pinToken;
            this.pinUvAuthProtocol = pinUvAuthProtocol;
            this.pinUvAuthParam = pinUvAuthParam;
        }
    }

    public BasicWebAuthnClient(Ctap2Session session) throws IOException, CommandException {
        this.ctap = session;

        Ctap2Session.InfoData info = ctap.getInfo();

        Map<String, ?> options = info.getOptions();

        final Boolean optionClientPin = (Boolean) options.get(OPTION_CLIENT_PIN);
        pinSupported = optionClientPin != null;

        this.clientPin =
                new ClientPin(ctap, getPreferredPinUvAuthProtocol(info.getPinUvAuthProtocols()));

        pinConfigured = pinSupported && Boolean.TRUE.equals(optionClientPin);

        Boolean uv = (Boolean) options.get(OPTION_USER_VERIFICATION);
        uvSupported = uv != null;
        uvConfigured = uvSupported && uv;

        enterpriseAttestationSupported = Boolean.TRUE.equals(options.get(OPTION_EP));
    }

    @Override
    public void close() throws IOException {
        ctap.close();
    }

    public UserAgentConfiguration getUserAgentConfiguration() {
        return userAgentConfiguration;
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
            @Nullable Integer enterpriseAttestation,
            @Nullable CommandState state
    ) throws IOException, CommandException, ClientError {
        byte[] clientDataHash = Utils.hash(clientDataJson);

        try {
            WithExtensionResults<Ctap2Session.CredentialData> result = ctapMakeCredential(
                    clientDataHash,
                    options,
                    effectiveDomain,
                    pin,
                    enterpriseAttestation,
                    state
            );

            final AttestationObject attestationObject = AttestationObject.fromCredential(result.data);

            AuthenticatorAttestationResponse response = new AuthenticatorAttestationResponse(
                    clientDataJson,
                    ctap.getCachedInfo().getTransports(),
                    attestationObject
            );

            return new PublicKeyCredential(
                    Objects.requireNonNull(attestationObject.getAuthenticatorData()
                            .getAttestedCredentialData()).getCredentialId(),
                    response,
                    result.clientExtensionResults);
        } catch (CtapException e) {
            if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
                throw new PinInvalidClientError(e, clientPin.getPinRetries().getCount());
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
        byte[] clientDataHash = Utils.hash(clientDataJson);
        try {
            final List<WithExtensionResults<Ctap2Session.AssertionData>> assertions = ctapGetAssertions(
                    clientDataHash,
                    options,
                    effectiveDomain,
                    pin,
                    state
            );

            final List<PublicKeyCredentialDescriptor> allowCredentials = removeUnsupportedCredentials(
                    options.getAllowCredentials()
            );

            if (assertions.size() == 1) {
                final WithExtensionResults<Ctap2Session.AssertionData> first = assertions.get(0);
                final Ctap2Session.AssertionData assertionData = first.data;
                final ClientExtensionResults clientExtensionResults = first.clientExtensionResults;

                return PublicKeyCredential.fromAssertion(
                        assertionData,
                        clientDataJson,
                        allowCredentials,
                        clientExtensionResults);
            } else {
                throw new MultipleAssertionsAvailable(clientDataJson, assertions);
            }

        } catch (CtapException e) {
            if (e.getCtapError() == CtapException.ERR_PIN_INVALID) {
                throw new PinInvalidClientError(e, clientPin.getPinRetries().getCount());
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
     * Check if the Authenticator supports Enterprise Attestation feature.
     *
     * @return true if the authenticator is enterprise attestation capable and enterprise
     * attestation is enabled.
     * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-feature-descriptions-enterp-attstn">Enterprise Attestation</a>
     */
    public boolean isEnterpriseAttestationSupported() {
        return enterpriseAttestationSupported;
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
    public CredentialManager getCredentialManager(char[] pin)
            throws IOException, CommandException, ClientError {
        if (!pinConfigured) {
            throw new ClientError(ClientError.Code.BAD_REQUEST,
                    "No PIN currently configured on this device");
        }
        try {
            return new CredentialManager(
                    new CredentialManagement(
                            ctap,
                            clientPin.getPinUvAuth(),
                            clientPin.getPinToken(pin, ClientPin.PIN_PERMISSION_CM, null)
                    )
            );
        } catch (CtapException e) {
            throw ClientError.wrapCtapException(e);
        }
    }

    static public class WithExtensionResults<T> {
        final T data;
        final ClientExtensionResults clientExtensionResults;

        WithExtensionResults(T data, ClientExtensionResults clientExtensionResults) {
            this.data = data;
            this.clientExtensionResults = clientExtensionResults;
        }

        public T getData() {
            return data;
        }

        public ClientExtensionResults getClientExtensionResults() {
            return clientExtensionResults;
        }
    }

    /**
     * Create a new WebAuthn credential.
     * <p>
     * This method is used internally in YubiKit and is not part of the public API. It may be changed
     * or removed at any time.
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
    protected WithExtensionResults<Ctap2Session.CredentialData> ctapMakeCredential(
            byte[] clientDataHash,
            PublicKeyCredentialCreationOptions options,
            String effectiveDomain,
            @Nullable char[] pin,
            @Nullable Integer enterpriseAttestation,
            @Nullable CommandState state
    ) throws IOException, CommandException, ClientError {

        final SerializationType serializationType = SerializationType.CBOR;

        Map<String, ?> rp = options.getRp().toMap(serializationType);
        String rpId = options.getRp().getId();
        if (rpId == null) {
            ((Map<String, Object>) rp).put("id", effectiveDomain);
        } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
            throw new ClientError(
                    ClientError.Code.BAD_REQUEST,
                    "RP ID is not valid for effective domain");
        }

        Map<String, Boolean> ctapOptions = getCreateCtapOptions(options, pin);
        Extension.CreateInputArguments inputArguments = new Extension.CreateInputArguments(ctap, options);
        Extensions extensions = Extensions.processExtensions(inputArguments);

        final AuthParams authParams = getAuthParams(
                clientDataHash,
                ctapOptions.containsKey(OPTION_USER_VERIFICATION),
                pin,
                extensions.getRequiredPermissions() |
                        ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA,
                rpId);

        final List<PublicKeyCredentialDescriptor> excludeCredentials =
                removeUnsupportedCredentials(
                        options.getExcludeCredentials()
                );

        PublicKeyCredentialDescriptor credToExclude = excludeCredentials != null
                ? Utils.filterCreds(
                ctap,
                rpId,
                excludeCredentials,
                effectiveDomain,
                authParams.pinUvAuthProtocol,
                authParams.pinToken)
                : null;

        final Map<String, ?> user = options.getUser().toMap(serializationType);

        List<Map<String, ?>> pubKeyCredParams = new ArrayList<>();
        for (PublicKeyCredentialParameters param : options.getPubKeyCredParams()) {
            if (isPublicKeyCredentialTypeSupported(param.getType())) {
                pubKeyCredParams.add(param.toMap(serializationType));
            }
        }

        @Nullable Integer validatedEnterpriseAttestation = null;
        if (isEnterpriseAttestationSupported() &&
                AttestationConveyancePreference.ENTERPRISE.equals(options.getAttestation()) &&
                userAgentConfiguration.supportsEpForRpId(rpId) &&
                enterpriseAttestation != null &&
                (enterpriseAttestation == 1 || enterpriseAttestation == 2)) {
            validatedEnterpriseAttestation = enterpriseAttestation;
        }

        Ctap2Session.CredentialData credentialData = ctap.makeCredential(
                clientDataHash,
                rp,
                user,
                pubKeyCredParams,
                credToExclude != null
                        ? Utils.getCredentialList(Collections.singletonList(credToExclude))
                        : null,
                extensions.getAuthenticatorInput(),
                ctapOptions.isEmpty() ? null : ctapOptions,
                authParams.pinUvAuthParam,
                authParams.pinUvAuthParam != null && authParams.pinUvAuthProtocol != null
                        ? authParams.pinUvAuthProtocol.getVersion()
                        : null,
                validatedEnterpriseAttestation,
                state
        );

        return new WithExtensionResults<>(credentialData,
                extensions.getResults(AttestationObject.fromCredential(credentialData)));
    }

    /**
     * Authenticate an existing WebAuthn credential.
     * <p>
     * This method is used internally in YubiKit and is not part of the public API. It may be changed
     * or removed at any time.
     * <p>
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
     * @throws IOException      A communication error in the transport layer
     * @throws CommandException A communication in the protocol layer
     * @throws ClientError      A higher level error
     */
    protected List<WithExtensionResults<Ctap2Session.AssertionData>> ctapGetAssertions(
            byte[] clientDataHash,
            PublicKeyCredentialRequestOptions options,
            String effectiveDomain,
            @Nullable char[] pin,
            @Nullable CommandState state
    ) throws IOException, CommandException, ClientError {
        String rpId = options.getRpId();
        if (rpId == null) {
            rpId = effectiveDomain;
        } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
            throw new ClientError(ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
        }
        Map<String, Boolean> ctapOptions = getRequestCtapOptions(options, pin);
        final List<PublicKeyCredentialDescriptor> allowCredentials = removeUnsupportedCredentials(
                options.getAllowCredentials()
        );

        final AuthParams filterCredAuthParams = getAuthParams(
                clientDataHash,
                ctapOptions.containsKey(OPTION_USER_VERIFICATION),
                pin,
                ClientPin.PIN_PERMISSION_GA,
                rpId);

        PublicKeyCredentialDescriptor selectedCred = allowCredentials != null && !allowCredentials.isEmpty()
                ? Utils.filterCreds(
                ctap,
                rpId,
                allowCredentials,
                effectiveDomain,
                filterCredAuthParams.pinUvAuthProtocol,
                filterCredAuthParams.pinToken)
                : null;

        final String fRpId = rpId;
        Extension.GetInputArguments inputArguments = new Extension.GetInputArguments(
                ctap,
                options,
                permissions -> {
                    try {
                        AuthParams authParams = getAuthParams(
                                clientDataHash,
                                ctapOptions.containsKey(OPTION_USER_VERIFICATION),
                                pin,
                                permissions,
                                fRpId);

                        if (authParams.pinToken == null || authParams.pinUvAuthProtocol == null) {
                            return null;
                        }

                        return new Pair<>(authParams.pinUvAuthProtocol, authParams.pinToken);
                    } catch (CommandException | ClientError | IOException e) {
                        Logger.debug(logger, "Failed to get auth params");
                        return null;
                    }
                },
                clientPin,
                selectedCred
        );

        Extensions extensions = Extensions.processExtensions(inputArguments);
        final AuthParams authParams = getAuthParams(
                clientDataHash,
                ctapOptions.containsKey(OPTION_USER_VERIFICATION),
                pin,
                ClientPin.PIN_PERMISSION_GA | extensions.getRequiredPermissions(),
                rpId);

        try {
            List<Ctap2Session.AssertionData> assertions = ctap.getAssertions(
                    rpId,
                    clientDataHash,
                    selectedCred != null
                            ? Utils.getCredentialList(Collections.singletonList(selectedCred))
                            : null,
                    extensions.getAuthenticatorInput(),
                    ctapOptions.isEmpty() ? null : ctapOptions,
                    authParams.pinUvAuthParam,
                    authParams.pinUvAuthParam != null && authParams.pinUvAuthProtocol != null
                            ? authParams.pinUvAuthProtocol.getVersion()
                            : null,
                    state
            );

            List<WithExtensionResults<Ctap2Session.AssertionData>> result = new ArrayList<>();
            for(final Ctap2Session.AssertionData assertionData : assertions) {
                // process extensions for each assertion
                result.add(
                        new WithExtensionResults<>(
                                assertionData,
                                extensions.getResults(assertionData)));
            }

            return result;

        } catch (CtapException exc) {
            if (exc.getCtapError() == CtapException.ERR_PIN_INVALID) {
                throw new PinInvalidClientError(exc, clientPin.getPinRetries().getCount());
            }
            throw ClientError.wrapCtapException(exc);
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

    private Map<String, Boolean> getCreateCtapOptions(
            PublicKeyCredentialCreationOptions publicKeyCredentialCreationOptions,
            @Nullable char[] pin) throws ClientError {
        Map<String, Boolean> ctapOptions = new HashMap<>();
        AuthenticatorSelectionCriteria authenticatorSelection =
                publicKeyCredentialCreationOptions.getAuthenticatorSelection();
        if (authenticatorSelection != null) {
            String residentKeyRequirement = authenticatorSelection.getResidentKey();
            if (ResidentKeyRequirement.REQUIRED.equals(residentKeyRequirement) ||
                    (ResidentKeyRequirement.PREFERRED.equals(residentKeyRequirement) &&
                            (pinSupported || uvSupported)
                    )
            ) {
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
        return ctapOptions;
    }

    private Map<String, Boolean> getRequestCtapOptions(
            PublicKeyCredentialRequestOptions options,
            @Nullable char[] pin) throws ClientError {
        Map<String, Boolean> ctapOptions = new HashMap<>();
        if (getCtapUv(options.getUserVerification(), pin != null)) {
            ctapOptions.put(OPTION_USER_VERIFICATION, true);
        }
        return ctapOptions;
    }

    private AuthParams getAuthParams(
            byte[] clientDataHash,
            boolean shouldUv,
            @Nullable char[] pin,
            @Nullable Integer permissions,
            @Nullable String rpId
    ) throws ClientError, IOException, CommandException {
        @Nullable byte[] authToken = null;
        @Nullable byte[] authParam = null;

        if (pin != null) {
            authToken = clientPin.getPinToken(pin, permissions, rpId);
            authParam = clientPin.getPinUvAuth().authenticate(authToken, clientDataHash);
        } else if (pinConfigured) {
            if (shouldUv && uvConfigured) {
                if (ClientPin.isTokenSupported(ctap.getCachedInfo())) {
                    authToken = clientPin.getUvToken(permissions, rpId, null);
                    authParam = clientPin.getPinUvAuth().authenticate(authToken, clientDataHash);
                }
                // no authToken is created means that internal UV is used
            } else {
                // the authenticator supports pin but no PIN was provided
                throw new PinRequiredClientError();
            }
        }
        return new AuthParams(
                authToken,
                clientPin.getPinUvAuth(),
                authParam);
    }

    /**
     * Calculates the preferred pinUvAuth protocol for authenticator provided list.
     * Returns PinUvAuthDummyProtocol if the authenticator does not support any of the SDK
     * supported protocols.
     */
    private PinUvAuthProtocol getPreferredPinUvAuthProtocol(List<Integer> pinUvAuthProtocols) {
        if (pinSupported) {
            for (int protocol : pinUvAuthProtocols) {
                if (protocol == PinUvAuthProtocolV1.VERSION) {
                    return new PinUvAuthProtocolV1();
                }

                if (protocol == PinUvAuthProtocolV2.VERSION) {
                    return new PinUvAuthProtocolV2();
                }
            }
        }

        return new PinUvAuthDummyProtocol();
    }

    private static boolean isPublicKeyCredentialTypeSupported(String type) {
        return PUBLIC_KEY.equals(type);
    }

    /**
     * @return new list containing only descriptors with valid {@code PublicKeyCredentialType} type
     */
    @Nullable
    private static List<PublicKeyCredentialDescriptor> removeUnsupportedCredentials(
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

    static class Utils {

        /**
         * @return first acceptable credential from the list available on the authenticator
         */
        @Nullable
        static PublicKeyCredentialDescriptor filterCreds(
                Ctap2Session ctap,
                @Nullable String rpId,
                List<PublicKeyCredentialDescriptor> descriptors,
                String effectiveDomain,
                @Nullable PinUvAuthProtocol pinUvAuthProtocol,
                @Nullable byte[] pinUvAuthToken
        ) throws IOException, CommandException, ClientError {

            if (rpId == null) {
                rpId = effectiveDomain;
            } else if (!(effectiveDomain.equals(rpId) || effectiveDomain.endsWith("." + rpId))) {
                throw new ClientError(ClientError.Code.BAD_REQUEST, "RP ID is not valid for effective domain");
            }

            List<PublicKeyCredentialDescriptor> creds;

            // filter out credential IDs which are too long
            Ctap2Session.InfoData info = ctap.getCachedInfo();
            Integer maxCredIdLength = info.getMaxCredentialIdLength();
            if (maxCredIdLength != null) {
                creds = descriptors
                        .stream()
                        .filter(desc -> desc.getId().length <= maxCredIdLength)
                        .collect(Collectors.toList());
            } else {
                creds = descriptors;
            }

            int maxCreds = info.getMaxCredentialCountInList() != null
                    ? info.getMaxCredentialCountInList()
                    : 1;

            List<List<PublicKeyCredentialDescriptor>> chunks = new ArrayList<>();
            for (int i = 0; i < creds.size(); i += maxCreds) {
                int last = Math.min(i + maxCreds, creds.size());
                chunks.add(creds.subList(i, last));
            }

            byte[] clientDataHash = new byte[32];
            Arrays.fill(clientDataHash, (byte) 0x00);

            byte[] pinAuth = null;
            Integer pinUvAuthVersion = null;
            if (pinUvAuthToken != null && pinUvAuthProtocol != null) {
                pinAuth = pinUvAuthProtocol.authenticate(pinUvAuthToken, clientDataHash);
                pinUvAuthVersion = pinUvAuthProtocol.getVersion();
            }

            for (List<PublicKeyCredentialDescriptor> chunk : chunks) {
                try {
                    List<Ctap2Session.AssertionData> assertions = ctap.getAssertions(
                            rpId,
                            clientDataHash,
                            getCredentialList(chunk),
                            null,
                            Collections.singletonMap("up", false),
                            pinAuth,
                            pinUvAuthVersion,
                            null
                    );

                    if (chunk.size() == 1) {
                        return chunk.get(0);
                    }

                    final Ctap2Session.AssertionData assertion = assertions.get(0);
                    final byte[] id = assertion.getCredentialId(null);

                    return new PublicKeyCredentialDescriptor(PUBLIC_KEY, id);

                } catch (CtapException ctapException) {
                    if (ctapException.getCtapError() == CtapException.ERR_NO_CREDENTIALS) {
                        continue;
                    }

                    throw ctapException;
                }
            }

            return null;
        }

        /**
         * @return new list of Credential descriptors for CBOR serialization.
         */
        @Nullable
        static List<Map<String, ?>> getCredentialList(@Nullable List<PublicKeyCredentialDescriptor> descriptors) {
            if (descriptors == null || descriptors.isEmpty()) {
                return null;
            }
            List<Map<String, ?>> list = new ArrayList<>();
            for (PublicKeyCredentialDescriptor credential : descriptors) {
                list.add(credential.toMap(SerializationType.CBOR));
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

}

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

package com.yubico.yubikit.fido.ctap;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.ApplicationSession;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.fido.FidoProtocol;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;

import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.annotation.Nullable;

/**
 * Implements CTAP 2.1
 *
 * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html">Client to Authenticator Protocol (CTAP)</a>
 */
@SuppressWarnings("unused")
public class Ctap2Session extends ApplicationSession<Ctap2Session> {

    private static final byte NFCCTAP_MSG = 0x10;

    public static final byte CMD_MAKE_CREDENTIAL = 0x01;
    public static final byte CMD_GET_ASSERTION = 0x02;
    public static final byte CMD_GET_INFO = 0x04;
    public static final byte CMD_CLIENT_PIN = 0x06;
    public static final byte CMD_RESET = 0x07;
    public static final byte CMD_GET_NEXT_ASSERTION = 0x08;
    public static final byte CMD_BIO_ENROLLMENT = 0x09;
    public static final byte CMD_CREDENTIAL_MANAGEMENT = 0x0A;
    public static final byte CMD_SELECTION = 0x0B;
    public static final byte CMD_LARGE_BLOBS = 0x0C;
    public static final byte CMD_CONFIG = 0x0D;
    public static final byte CMD_BIO_ENROLLMENT_PRE = 0x40;
    public static final byte CMD_CREDENTIAL_MANAGEMENT_PRE = 0x41;

    private final Version version;
    private final Backend<?> backend;
    private final InfoData info;

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Ctap2Session.class);

    /**
     * Construct a new Ctap2Session for a given YubiKey
     *
     * @param device   a YubiKeyDevice over NFC or USB.
     * @param callback a callback to invoke with the session.
     */
    public static void create(YubiKeyDevice device, Callback<Result<Ctap2Session, Exception>> callback) {
        if (device.supportsConnection(FidoConnection.class)) {
            device.requestConnection(FidoConnection.class, value -> callback.invoke(Result.of(() -> new Ctap2Session(value.getValue()))));
        } else if (device.supportsConnection(SmartCardConnection.class)) {
            device.requestConnection(SmartCardConnection.class, value -> callback.invoke(Result.of(() -> new Ctap2Session(value.getValue()))));
        } else {
            callback.invoke(Result.failure(new ApplicationNotAvailableException("Session does not support any compatible connection type")));
        }
    }

    public Ctap2Session(SmartCardConnection connection)
            throws IOException, ApplicationNotAvailableException, CommandException {
        SmartCardProtocol protocol = new SmartCardProtocol(connection);
        protocol.select(AppId.FIDO);
        // it is not possible to get the applet version over NFC/CCID
        version = new Version(0, 0, 0);
        backend = new Backend<SmartCardProtocol>(protocol) {
            @Override
            byte[] sendCbor(byte[] data, @Nullable CommandState state) throws IOException, CommandException {
                //Cancellation is not implemented for NFC, and most likely not needed.
                return delegate.sendAndReceive(new Apdu(0x80, NFCCTAP_MSG, 0x00, 0x00, data));
            }
        };
        info = getInfo();
        Logger.debug(logger, "Ctap2Session session initialized for connection={}",
                connection.getClass().getSimpleName());
    }

    public Ctap2Session(FidoConnection connection) throws IOException, CommandException {
        FidoProtocol protocol = new FidoProtocol(connection);
        version = protocol.getVersion();
        backend = new Backend<FidoProtocol>(protocol) {
            @Override
            byte[] sendCbor(byte[] data, @Nullable CommandState state) throws IOException {
                return delegate.sendAndReceive(FidoProtocol.CTAPHID_CBOR, data, state);
            }
        };
        info = getInfo();
        Logger.debug(logger, "Ctap2Session session initialized for connection={}, version={}",
                connection.getClass().getSimpleName(),
                version);
    }

    /**
     * Packs a list of objects into a 1-indexed map, discarding any null values.
     */
    private static Map<Integer, ?> args(Object... params) {
        Map<Integer, Object> argMap = new HashMap<>();
        for (int i = 0; i < params.length; i++) {
            if (params[i] != null) {
                argMap.put(i + 1, params[i]);
            }
        }
        return argMap;
    }

    private Map<Integer, ?> sendCbor(
            byte command,
            @Nullable Object payload,
            @Nullable CommandState state
    ) throws IOException, CommandException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(command);
        if (payload != null) {
            Cbor.encodeTo(baos, payload);
        }

        logger.debug("{}", StringUtils.bytesToHex(baos.toByteArray()));
        byte[] response = backend.sendCbor(baos.toByteArray(), state);
        byte status = response[0];
        if (status != 0x00) {
            throw new CtapException(status);
        }
        if (response.length == 1) {
            return Collections.emptyMap(); // Empty response
        }

        try {
            @SuppressWarnings("unchecked")
            Map<Integer, ?> value = (Map<Integer, ?>) Cbor.decode(response, 1, response.length - 1);
            return value != null ? value : Collections.emptyMap();
        } catch (ClassCastException e) {
            throw new BadResponseException("Unexpected CBOR data in response");
        }
    }

    /**
     * This method is invoked by the host to request generation of a new credential in the
     * authenticator.
     *
     * @param clientDataHash        a SHA-256 hash of the clientDataJson
     * @param rp                    a Map containing the RpEntity data
     * @param user                  a Map containing the UserEntity data
     * @param pubKeyCredParams      a List of Maps containing the supported credential algorithms
     * @param excludeList           a List of Maps of already registered credentials
     * @param extensions            a Map of CTAP extension inputs
     * @param options               a Map of CTAP options
     * @param pinUvAuthParam        a byte array derived from a pinToken
     * @param pinUvAuthProtocol     the PIN protocol version used for the pinUvAuthParam
     * @param enterpriseAttestation an enterprise attestation request
     * @param state                 an optional state object to cancel a request and handle
     *                              keepalive signals
     * @return a new credential
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorMakeCredential">authenticatorMakeCredential</a>
     */
    public CredentialData makeCredential(
            byte[] clientDataHash,
            Map<String, ?> rp,
            Map<String, ?> user,
            List<Map<String, ?>> pubKeyCredParams,
            @Nullable List<Map<String, ?>> excludeList,
            @Nullable Map<String, ?> extensions,
            @Nullable Map<String, ?> options,
            @Nullable byte[] pinUvAuthParam,
            @Nullable Integer pinUvAuthProtocol,
            @Nullable Integer enterpriseAttestation,
            @Nullable CommandState state
    ) throws IOException, CommandException {
        Logger.debug(logger, "makeCredential for clientDataHash={},rp={},user={}," +
                        "pubKeyCredParams={},excludeList={},extensions={},options={}," +
                        "pinUvAuthParam={},pinUvAuthProtocol={},enterpriseAttestation={},state={}",
                clientDataHash, rp, user, pubKeyCredParams, excludeList, extensions, options,
                pinUvAuthParam, pinUvAuthProtocol, enterpriseAttestation, state);

        Logger.trace(logger,
                "Call CMD_MAKE_CREDENTIAL ({})",
                String.format("0x%02X", CMD_MAKE_CREDENTIAL));

        final Map<Integer, ?> data = sendCbor(CMD_MAKE_CREDENTIAL, args(
                        clientDataHash,
                        rp,
                        user,
                        pubKeyCredParams,
                        excludeList,
                        extensions,
                        options,
                        pinUvAuthParam,
                        pinUvAuthProtocol,
                        enterpriseAttestation),
                state);

        CredentialData credentialData = CredentialData.fromData(data);
        Logger.info(logger, "Credential created");
        return credentialData;
    }

    /**
     * This method is used by a host to request cryptographic proof of user authentication as well
     * as user consent to a given transaction, using a previously generated credential that is bound
     * to the authenticator and relying party identifier.
     *
     * @param rpId              the RP ID for the request
     * @param clientDataHash    a SHA-256 hash of the clientDataJson
     * @param allowList         a List of Maps of already registered credentials
     * @param extensions        a Map of CTAP extension inputs
     * @param options           a Map of CTAP options
     * @param pinUvAuthParam    a byte array derived from a pinToken
     * @param pinUvAuthProtocol the PIN protocol version used for the pinUvAuthParam
     * @param state             used to cancel a request and handle keepalive signals
     * @return a List of available assertions
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetAssertion">authenticatorGetAssertion</a>
     * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetNextAssertion">authenticatorGetNextAssertion</a>
     */
    public List<AssertionData> getAssertions(
            String rpId,
            byte[] clientDataHash,
            @Nullable List<Map<String, ?>> allowList,
            @Nullable Map<String, ?> extensions,
            @Nullable Map<String, ?> options,
            @Nullable byte[] pinUvAuthParam,
            @Nullable Integer pinUvAuthProtocol,
            @Nullable CommandState state
    ) throws IOException, CommandException {
        Logger.debug(logger, "getAssertions for rpId={},clientDataHash={}," +
                        "allowList={},extensions={},options={},pinUvAuthParam={}," +
                        "pinUvAuthProtocol={},state={}",
                rpId, clientDataHash, allowList, extensions, options, pinUvAuthParam, pinUvAuthProtocol);

        Logger.trace(logger,
                "Call CMD_GET_ASSERTION ({})",
                String.format("0x%02X", CMD_GET_ASSERTION));

        final Map<Integer, ?> assertion = sendCbor(CMD_GET_ASSERTION, args(
                        rpId,
                        clientDataHash,
                        allowList,
                        extensions,
                        options,
                        pinUvAuthParam,
                        pinUvAuthProtocol),
                state);
        List<AssertionData> assertions = new ArrayList<>();
        assertions.add(AssertionData.fromData(assertion));
        Integer nCreds = (Integer) assertion.get(AssertionData.RESULT_N_CREDS);
        int credentialCount = nCreds != null ? nCreds : 1;
        for (int i = credentialCount; i > 1; i--) {
            assertions.add(AssertionData.fromData(Objects.requireNonNull(sendCbor(CMD_GET_NEXT_ASSERTION, null, null))));
        }
        Logger.info(logger, "Authenticator returned {} assertions.", credentialCount);
        return assertions;
    }

    /**
     * Using this method, platforms can request that the authenticator report a list of its
     * supported protocol versions and extensions, its AAGUID, and other aspects of its overall
     * capabilities. Platforms should use this information to tailor their command parameters
     * choices.
     *
     * @return an InfoData object with information about the YubiKey
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetInfo">authenticatorGetInfo</a>
     */
    public InfoData getInfo() throws IOException, CommandException {
        Logger.trace(logger,
                "Call CMD_GET_INFO ({})",
                String.format("0x%02X", CMD_GET_INFO));
        final Map<Integer, ?> infoData = sendCbor(CMD_GET_INFO, null, null);
        final InfoData info = InfoData.fromData(infoData);
        Logger.trace(logger, "Ctap2.InfoData: {}", info);
        return info;
    }

    /**
     * This command exists so that plaintext PINs are not sent to the authenticator.
     *
     * @param pinUvAuthProtocol PIN/UV protocol version chosen by the platform.
     * @param subCommand        The specific action being requested.
     * @param keyAgreement      The platform key-agreement key.
     * @param pinUvAuthParam    The output of calling authenticate(key, message) → signature on some
     *                          context specific to the subcommand.
     * @param newPinEnc         An encrypted PIN.
     * @param pinHashEnc        An encrypted proof-of-knowledge of a PIN.
     * @param permissions       Bitfield of permissions.
     * @param rpId              The RP ID to assign as the permissions RP ID.
     * @return an InfoData object with information about the YubiKey
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorClientPIN">authenticatorClientPIN</a>
     */
    Map<Integer, ?> clientPin(
            @Nullable Integer pinUvAuthProtocol,
            int subCommand,
            @Nullable Map<Integer, ?> keyAgreement,
            @Nullable byte[] pinUvAuthParam,
            @Nullable byte[] newPinEnc,
            @Nullable byte[] pinHashEnc,
            @Nullable Integer permissions,
            @Nullable String rpId,
            @Nullable CommandState state
    ) throws IOException, CommandException {
        Logger.debug(logger, "clientPin for pinUvAuthProtocol={},subCommand={}," +
                        "keyAgreement={},pinUvAuthParam={},newPinEnc={},pinHashEnc={}," +
                        "permissions={},rpId={}", pinUvAuthProtocol, subCommand, keyAgreement,
                pinUvAuthParam, newPinEnc, pinHashEnc, permissions, rpId);
        Logger.trace(logger,
                "Call CMD_CLIENT_PIN ({})",
                String.format("0x%02X", CMD_CLIENT_PIN));
        return sendCbor(
                CMD_CLIENT_PIN, args(
                        pinUvAuthProtocol,
                        subCommand,
                        keyAgreement,
                        pinUvAuthParam,
                        newPinEnc,
                        pinHashEnc,
                        null,
                        null,
                        permissions,
                        rpId
                ), state);
    }

    /**
     * Issues a CTAP2 reset, which will delete/invalidate all FIDO credentials.
     * <p>
     * NOTE: Over USB this command must be sent within a few seconds of plugging the YubiKey in, and
     * it requires touch confirmation.
     *
     * @param state If needed, the state to provide control over the ongoing operation.
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorReset">authenticatorReset</a>
     */
    public void reset(@Nullable CommandState state) throws IOException, CommandException {
        Logger.trace(logger,
                "Call CMD_RESET ({})",
                String.format("0x%02X", CMD_RESET));
        sendCbor(CMD_RESET, null, state);
    }

    /**
     * This command is used by the platform to manage discoverable credentials on the
     * authenticator.
     *
     * @param command           Either CMD_CREDENTIAL_MANAGEMENT or CMD_CREDENTIAL_MANAGEMENT_PRE
     * @param subCommand        The subCommand currently being requested
     * @param subCommandParams  A map of subCommands parameters.
     * @param pinUvAuthProtocol PIN/UV protocol version chosen by the platform.
     * @param pinUvAuthParam    First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorCredentialManagement">authenticatorCredentialManagement</a>
     */
    Map<Integer, ?> credentialManagement(
            byte command,
            int subCommand,
            @Nullable Map<?, ?> subCommandParams,
            @Nullable Integer pinUvAuthProtocol,
            @Nullable byte[] pinUvAuthParam
    ) throws IOException, CommandException {
        Logger.trace(logger,
                "Call CMD_CREDENTIAL_MANAGEMENT ({})",
                String.format("0x%02X", command));
        return sendCbor(command, args(
                subCommand,
                subCommandParams,
                pinUvAuthProtocol,
                pinUvAuthParam), null);
    }

    /**
     * This command allows the platform to let a user select a certain authenticator by asking for
     * user presence.
     *
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorSelection">authenticatorSelection</a>
     */
    public void selection(@Nullable CommandState state) throws IOException, CommandException {
        Logger.trace(logger,
                "Call CMD_SELECTION ({})",
                String.format("0x%02X", CMD_SELECTION));
        sendCbor(CMD_SELECTION, null, state);
    }

    /**
     * This command is used to configure various authenticator features through the use of its
     * subcommands.
     * <p>
     * Note: Platforms MUST NOT invoke this command unless the authnrCfg option ID is present and
     * true in the response to an authenticatorGetInfo command.
     *
     * @param subCommand        The subCommand currently being requested
     * @param subCommandParams  A map of subCommands parameters.
     * @param pinUvAuthProtocol PIN/UV protocol version chosen by the platform.
     * @param pinUvAuthParam    First 16 bytes of HMAC-SHA-256 of contents using pinUvAuthToken.
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorConfig">authenticatorConfig</a>
     */
    public Map<Integer, ?> config(
            byte subCommand,
            @Nullable Map<?, ?> subCommandParams,
            @Nullable Integer pinUvAuthProtocol,
            @Nullable byte[] pinUvAuthParam
    ) throws IOException, CommandException {
        Logger.trace(logger,
                "Call CMD_CONFIG ({})",
                String.format("0x%02X", CMD_CONFIG));
        return sendCbor(CMD_CONFIG, args(
                subCommand,
                subCommandParams,
                pinUvAuthParam != null ? pinUvAuthProtocol : null,
                pinUvAuthParam), null);
    }

    @Override
    public void close() throws IOException {
        backend.close();
    }

    @Override
    public Version getVersion() {
        return version;
    }

    public InfoData getCachedInfo() {
        return info;
    }

    private static abstract class Backend<T extends Closeable> implements Closeable {
        protected final T delegate;

        private Backend(T delegate) {
            this.delegate = delegate;
        }

        @Override
        public void close() throws IOException {
            delegate.close();
        }

        abstract byte[] sendCbor(byte[] data, @Nullable CommandState state) throws IOException, CommandException;
    }

    /**
     * Data object containing the information readable form a YubiKey using the getInfo command.
     *
     * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorGetInfo">authenticatorGetInfo</a>
     */
    public static class InfoData {
        private final static int RESULT_VERSIONS = 0x01;
        private final static int RESULT_EXTENSIONS = 0x02;
        private final static int RESULT_AAGUID = 0x03;
        private final static int RESULT_OPTIONS = 0x04;
        private final static int RESULT_MAX_MSG_SIZE = 0x05;
        private final static int RESULT_PIN_UV_AUTH_PROTOCOLS = 0x06;
        private final static int RESULT_MAX_CREDS_IN_LIST = 0x07;
        private final static int RESULT_MAX_CRED_ID_LENGTH = 0x08;
        private final static int RESULT_TRANSPORTS = 0x09;
        private final static int RESULT_ALGORITHMS = 0x0A;
        private final static int RESULT_MAX_SERIALIZED_LARGE_BLOB_ARRAY = 0x0B;
        private final static int RESULT_FORCE_PIN_CHANGE = 0x0C;
        private final static int RESULT_MIN_PIN_LENGTH = 0x0D;
        private final static int RESULT_FIRMWARE_VERSION = 0x0E;
        private final static int RESULT_MAX_CRED_BLOB_LENGTH = 0x0F;
        private final static int RESULT_MAX_RPID_FOR_SET_MIN_PIN_LENGTH = 0x10;
        private final static int RESULT_PREFERRED_PLATFORM_UV_ATTEMPTS = 0x11;
        private final static int RESULT_UV_MODALITY = 0x12;
        private final static int RESULT_CERTIFICATIONS = 0x13;
        private final static int RESULT_REMAINING_DISCOVERABLE_CREDENTIALS = 0x14;
        private final static int RESULT_VENDOR_PROTOTYPE_CONFIG_COMMANDS = 0x15;

        private final List<String> versions;
        private final List<String> extensions;
        private final byte[] aaguid;
        private final int maxMsgSize;
        private final Map<String, Object> options;
        @Nullable
        private final List<Integer> pinUvAuthProtocols;
        @Nullable
        private final Integer maxCredentialCountInList;
        @Nullable
        private final Integer maxCredentialIdLength;
        private final List<String> transports;
        @Nullable
        private final List<PublicKeyCredentialParameters> algorithms;
        @Nullable
        private final Integer maxSerializedLargeBlobArray;
        @Nullable
        private final Boolean forcePINChange;
        @Nullable
        private final Integer minPINLength;
        @Nullable
        private final Integer firmwareVersion;
        @Nullable
        private final Integer maxCredBlobLength;
        @Nullable
        private final Integer maxRPIDsForSetMinPINLength;
        @Nullable
        private final Integer preferredPlatformUvAttempts;
        @Nullable
        private final Integer uvModality;
        @Nullable
        private final Map<String, Object> certifications;
        @Nullable
        private final Integer remainingDiscoverableCredentials;
        @Nullable
        private final List<Integer> vendorPrototypeConfigCommands;

        private InfoData(
                List<String> versions,
                List<String> extensions,
                byte[] aaguid,
                Map<String, Object> options,
                int maxMsgSize,
                @Nullable
                List<Integer> pinUvAuthProtocols,
                @Nullable Integer maxCredentialCountInList,
                @Nullable Integer maxCredentialIdLength,
                List<String> transports,
                @Nullable List<PublicKeyCredentialParameters> algorithms,
                @Nullable Integer maxSerializedLargeBlobArray,
                @Nullable Boolean forcePINChange,
                @Nullable Integer minPINLength,
                @Nullable Integer firmwareVersion,
                @Nullable Integer maxCredBlobLength,
                @Nullable Integer maxRPIDsForSetMinPINLength,
                @Nullable Integer preferredPlatformUvAttempts,
                @Nullable Integer uvModality,
                @Nullable Map<String, Object> certifications,
                @Nullable Integer remainingDiscoverableCredentials,
                @Nullable List<Integer> vendorPrototypeConfigCommands) {
            this.versions = versions;
            this.extensions = extensions;
            this.aaguid = aaguid;
            this.options = options;
            this.maxMsgSize = maxMsgSize;
            this.pinUvAuthProtocols = pinUvAuthProtocols;
            this.maxCredentialCountInList = maxCredentialCountInList;
            this.maxCredentialIdLength = maxCredentialIdLength;
            this.transports = transports;
            this.algorithms = algorithms;
            this.maxSerializedLargeBlobArray = maxSerializedLargeBlobArray;
            this.forcePINChange = forcePINChange;
            this.minPINLength = minPINLength;
            this.firmwareVersion = firmwareVersion;
            this.maxCredBlobLength = maxCredBlobLength;
            this.maxRPIDsForSetMinPINLength = maxRPIDsForSetMinPINLength;
            this.preferredPlatformUvAttempts = preferredPlatformUvAttempts;
            this.uvModality = uvModality;
            this.certifications = certifications;
            this.remainingDiscoverableCredentials = remainingDiscoverableCredentials;
            this.vendorPrototypeConfigCommands = vendorPrototypeConfigCommands;

        }

        @SuppressWarnings("unchecked")
        private static InfoData fromData(Map<Integer, ?> data) {
            return new InfoData(
                    (List<String>) data.get(RESULT_VERSIONS),
                    data.containsKey(RESULT_EXTENSIONS)
                            ? (List<String>) data.get(RESULT_EXTENSIONS)
                            : Collections.emptyList(),
                    (byte[]) data.get(RESULT_AAGUID),
                    data.containsKey(RESULT_OPTIONS)
                            ? (Map<String, Object>) data.get(RESULT_OPTIONS)
                            : Collections.emptyMap(),
                    data.containsKey(RESULT_MAX_MSG_SIZE)
                            ? (Integer) data.get(RESULT_MAX_MSG_SIZE)
                            : 1024,
                    data.containsKey(RESULT_PIN_UV_AUTH_PROTOCOLS)
                            ? (List<Integer>) data.get(RESULT_PIN_UV_AUTH_PROTOCOLS)
                            : Collections.emptyList(),
                    (Integer) data.get(RESULT_MAX_CREDS_IN_LIST),
                    (Integer) data.get(RESULT_MAX_CRED_ID_LENGTH),
                    data.containsKey(RESULT_TRANSPORTS)
                            ? (List<String>) data.get(RESULT_TRANSPORTS)
                            : Collections.emptyList(),
                    (List<PublicKeyCredentialParameters>) data.get(RESULT_ALGORITHMS),
                    (Integer) data.get(RESULT_MAX_SERIALIZED_LARGE_BLOB_ARRAY),
                    (Boolean) data.get(RESULT_FORCE_PIN_CHANGE),
                    (Integer) data.get(RESULT_MIN_PIN_LENGTH),
                    (Integer) data.get(RESULT_FIRMWARE_VERSION),
                    (Integer) data.get(RESULT_MAX_CRED_BLOB_LENGTH),
                    (Integer) data.get(RESULT_MAX_RPID_FOR_SET_MIN_PIN_LENGTH),
                    (Integer) data.get(RESULT_PREFERRED_PLATFORM_UV_ATTEMPTS),
                    (Integer) data.get(RESULT_UV_MODALITY),
                    (Map<String, Object>) data.get(RESULT_CERTIFICATIONS),
                    (Integer) data.get(RESULT_REMAINING_DISCOVERABLE_CREDENTIALS),
                    (List<Integer>) data.get(RESULT_VENDOR_PROTOTYPE_CONFIG_COMMANDS)
            );
        }

        /**
         * List of supported versions.
         * <p>
         * Supported versions are: "FIDO_2_0" for CTAP2 / FIDO2 / Web Authentication authenticators and "U2F_V2" for CTAP1/U2F authenticators.
         *
         * @return list of supported versions
         */
        public List<String> getVersions() {
            return versions;
        }

        /**
         * List of supported extensions.
         *
         * @return list of supported extensions
         */
        public List<String> getExtensions() {
            return extensions;
        }

        /**
         * Get the claimed AAGUID of the YubiKey.
         *
         * @return the AAGUID of the YubiKey
         */
        public byte[] getAaguid() {
            return aaguid;
        }

        /**
         * Get the options map, which defines which options are supported, and their configuration.
         *
         * @return a Map of supported options
         */
        public Map<String, ?> getOptions() {
            return options;
        }

        /**
         * Get maximum message size supported by the authenticator.
         *
         * @return maximum message size
         */
        public int getMaxMsgSize() {
            return maxMsgSize;
        }

        /**
         * Get a list of the supported PIN/UV Auth protocol versions.
         *
         * @return a list of supported versions.
         */
        @Nullable
        public List<Integer> getPinUvAuthProtocols() {
            return pinUvAuthProtocols;
        }

        /**
         * @return Maximum number of credentials supported in credentialID list
         * at a time by the authenticator.
         */
        @Nullable
        Integer getMaxCredentialCountInList() {
            return maxCredentialCountInList;
        }

        /**
         * @return Maximum Credential ID Length supported by the authenticator.
         */
        @Nullable
        Integer getMaxCredentialIdLength() {
            return maxCredentialIdLength;
        }

        /**
         * @return List of supported transports. Values are taken from the AuthenticatorTransport
         * enum in WebAuthn.
         * @see <a href="https://www.w3.org/TR/webauthn/#enumdef-authenticatortransport">AuthenticatorTransport
         * enum</a>
         */
        public List<String> getTransports() {
            return transports;
        }

        /**
         * @return List of supported algorithms for credential generation, as specified in WebAuthn.
         */
        @Nullable
        public List<PublicKeyCredentialParameters> getAlgorithms() {
            return algorithms;
        }

        /**
         * @return The maximum size, in bytes, of the serialized large-blob array that this
         * authenticator can store.
         * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorLargeBlobs">
         * 6.10. authenticatorLargeBlobs (0x0C)</a>
         */
        @Nullable
        public Integer getMaxSerializedLargeBlobArray() {
            return maxSerializedLargeBlobArray;
        }

        /**
         * Returns requirement whether the authenticator requires PIN Change before use.
         *
         * @return force PIN Change requirement.
         * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#changingExistingPin">PIN Change</a>
         */
        @Nullable
        public Boolean getForcePINChange() {
            return forcePINChange;
        }

        /**
         * @return The current minimum PIN length, in Unicode code points, the authenticator
         * enforces for ClientPIN.
         */
        @Nullable
        public Integer getMinPINLength() {
            return minPINLength;
        }

        /**
         * @return The firmware version of the authenticator model identified by AAGUID.
         */
        @Nullable
        Integer getFirmwareVersion() {
            return firmwareVersion;
        }

        /**
         * @return Maximum credBlob length in bytes supported by the authenticator.
         */
        @Nullable
        public Integer getMaxCredBlobLength() {
            return maxCredBlobLength;
        }

        /**
         * @return The max number of RP IDs that authenticator can set via setMinPINLength
         * subcommand.
         */
        @Nullable
        public Integer getMaxRPIDsForSetMinPINLength() {
            return maxRPIDsForSetMinPINLength;
        }

        /**
         * @return The preferred number of invocations of the
         * getPinUvAuthTokenUsingUvWithPermissions subCommand the platform may attempt before
         * falling back to the getPinUvAuthTokenUsingPinWithPermissions subCommand or displaying
         * an error.
         */
        @Nullable
        public Integer getPreferredPlatformUvAttempts() {
            return preferredPlatformUvAttempts;
        }

        /**
         * @return The user verification modality supported by the authenticator via
         * authenticatorClientPIN's getPinUvAuthTokenUsingUvWithPermissions subcommand.
         */
        @Nullable
        public Integer getUvModality() {
            return uvModality;
        }

        /**
         * Provides a hint to the platform with additional information about certifications that
         * the authenticator has received.
         *
         * @return Certifications in the form key-value pairs with string IDs and integer values.
         * @see <a href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#sctn-feature-descriptions-certifications">Authenticator Certifications</a>
         */
        @Nullable
        public final Map<String, Object> getCertifications() {
            return certifications;
        }

        /**
         * @return The estimated number of additional discoverable credentials that can be stored.
         */
        @Nullable
        public Integer getRemainingDiscoverableCredentials() {
            return remainingDiscoverableCredentials;
        }

        /**
         * @return List of authenticatorConfig vendorCommandId values supported.
         */
        @Nullable
        public List<Integer> getVendorPrototypeConfigCommands() {
            return vendorPrototypeConfigCommands;
        }

        @Override
        public String toString() {
            return "Ctap2Session.InfoData{" +
                    "versions=" + versions +
                    ", extensions=" + extensions +
                    ", aaguid=" + StringUtils.bytesToHex(aaguid) +
                    ", options=" + options +
                    ", maxMsgSize=" + maxMsgSize +
                    ", pinUvAuthProtocols=" + pinUvAuthProtocols +
                    ", maxCredentialCountInList=" + maxCredentialCountInList +
                    ", maxCredentialIdLength=" + maxCredentialIdLength +
                    ", transports=" + transports +
                    ", algorithms=" + algorithms +
                    ", maxSerializedLargeBlobArray=" + maxSerializedLargeBlobArray +
                    ", forcePINChange=" + forcePINChange +
                    ", minPINLength=" + minPINLength +
                    ", firmwareVersion=" + firmwareVersion +
                    ", maxCredBlobLength=" + maxCredBlobLength +
                    ", maxRPIDsForSetMinPINLength=" + maxRPIDsForSetMinPINLength +
                    ", preferredPlatformUvAttempts=" + preferredPlatformUvAttempts +
                    ", uvModality=" + uvModality +
                    ", certifications=" + certifications +
                    ", remainingDiscoverableCredentials=" + remainingDiscoverableCredentials +
                    ", vendorPrototypeConfigCommands=" + vendorPrototypeConfigCommands +
                    '}';
        }
    }

    /**
     * Data class holding the result of makeCredential.
     */
    public static class CredentialData {
        private final static int RESULT_FMT = 0x01;
        private final static int RESULT_AUTH_DATA = 0x02;
        private final static int RESULT_ATT_STMT = 0x03;
        private final static int RESULT_EP_ATT = 0x04;
        private final static int RESULT_LARGE_BLOB_KEY = 0x05;

        private final String format;
        private final byte[] authenticatorData;
        private final Map<String, ?> attestationStatement;
        @Nullable
        private final Boolean enterpriseAttestation;
        @Nullable
        private final byte[] largeBlobKey;

        private CredentialData(
                String format,
                byte[] authenticatorData,
                Map<String, ?> attestationStatement,
                @Nullable Boolean enterpriseAttestation,
                @Nullable byte[] largeBlobKey
        ) {
            this.format = format;
            this.authenticatorData = authenticatorData;
            this.attestationStatement = attestationStatement;
            this.enterpriseAttestation = enterpriseAttestation;
            this.largeBlobKey = largeBlobKey;
        }

        @SuppressWarnings("unchecked")
        private static CredentialData fromData(Map<Integer, ?> data) {
            return new CredentialData(
                    Objects.requireNonNull((String) data.get(RESULT_FMT)),
                    Objects.requireNonNull((byte[]) data.get(RESULT_AUTH_DATA)),
                    Objects.requireNonNull((Map<String, ?>) data.get(RESULT_ATT_STMT)),
                    (Boolean) data.get(RESULT_EP_ATT),
                    (byte[]) data.get(RESULT_LARGE_BLOB_KEY)
            );
        }

        /**
         * The AuthenticatorData object.
         *
         * @return the AuthenticatorData
         * @see <a href="https://www.w3.org/TR/webauthn/#authenticator-data">authenticator-data</a>
         */
        public byte[] getAuthenticatorData() {
            return authenticatorData;
        }

        /**
         * The attestation statement format identifier.
         *
         * @return the format of the attestation
         */
        public String getFormat() {
            return format;
        }

        /**
         * The attestation statement, whose format is identified by the "fmt" object member.
         *
         * @return the attestation statement
         */
        public Map<String, ?> getAttestationStatement() {
            return attestationStatement;
        }

        /**
         * Indicates whether an enterprise attestation was returned for this credential.
         *
         * @return null or false if enterprise attestation was not returned, otherwise true.
         */
        @Nullable
        public Boolean getEnterpriseAttestation() {
            return enterpriseAttestation;
        }

        /**
         * The largeBlobKey for the credential, if requested with the largeBlobKey extension.
         *
         * @return The largeBlobKey for the credential.
         */
        @Nullable
        public byte[] getLargeBlobKey() {
            return largeBlobKey;
        }
    }

    /**
     * Data class holding the result of getAssertion.
     */
    public static class AssertionData {
        private final static int RESULT_CREDENTIAL = 1;
        private final static int RESULT_AUTH_DATA = 2;
        private final static int RESULT_SIGNATURE = 3;
        private final static int RESULT_USER = 4;
        private final static int RESULT_N_CREDS = 5;

        @Nullable
        private final Map<String, ?> credential;
        @Nullable
        private final Map<String, ?> user;
        private final byte[] signature;
        private final byte[] authenticatorData;

        private AssertionData(@Nullable Map<String, ?> credential, @Nullable Map<String, ?> user, byte[] signature, byte[] authenticatorData) {
            this.credential = credential;
            this.user = user;
            this.signature = signature;
            this.authenticatorData = authenticatorData;
        }

        @SuppressWarnings("unchecked")
        private static AssertionData fromData(Map<Integer, ?> data) {
            return new AssertionData(
                    (Map<String, ?>) data.get(RESULT_CREDENTIAL),
                    (Map<String, ?>) data.get(RESULT_USER),
                    Objects.requireNonNull((byte[]) data.get(RESULT_SIGNATURE)),
                    Objects.requireNonNull((byte[]) data.get(RESULT_AUTH_DATA))
            );
        }

        /**
         * The user structure containing account information.
         *
         * @return the user structure for the assertion
         */
        @Nullable
        public Map<String, ?> getUser() {
            return user;
        }

        /**
         * The credential identifier whose private key was used to generate the assertion.
         *
         * @return the credential descriptor for the assertion
         */
        @Nullable
        public Map<String, ?> getCredential() {
            return credential;
        }

        /**
         * The assertion signature produced by the authenticator
         *
         * @return the signature for the assertion
         */
        public byte[] getSignature() {
            return signature;
        }

        /**
         * The AuthenticatorData object.
         *
         * @return the AuthenticatorData
         * @see <a href="https://www.w3.org/TR/webauthn/#authenticator-data">authenticator-data</a>
         */
        public byte[] getAuthenticatorData() {
            return authenticatorData;
        }

        /**
         * Helper function for obtaining credential id for AssertionData with help of allowCredentials
         *
         * @param allowCredentials list of allowed credentials which might help to get correct
         *                         credential id
         * @return credentialId for assertion
         * @throws RuntimeException if credential id could not be computed
         */
        public byte[] getCredentialId(
                @Nullable List<PublicKeyCredentialDescriptor> allowCredentials
        ) {
            byte[] credentialId;
            Map<String, ?> credentialMap = getCredential();
            if (credentialMap != null) {
                credentialId = Objects.requireNonNull((byte[]) credentialMap.get(PublicKeyCredentialDescriptor.ID));
            } else {
                // Credential is optional if allowList contains exactly one credential.
                if (allowCredentials == null || allowCredentials.size() != 1) {
                    throw new RuntimeException("Expecting exactly one valid credential in allowCredentials");
                }
                credentialId = allowCredentials.get(0).getId();
            }
            return credentialId;
        }
    }
}
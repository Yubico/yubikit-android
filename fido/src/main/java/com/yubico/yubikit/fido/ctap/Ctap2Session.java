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

    private static final byte CMD_MAKE_CREDENTIAL = 0x01;
    private static final byte CMD_GET_ASSERTION = 0x02;
    private static final byte CMD_GET_INFO = 0x04;
    private static final byte CMD_CLIENT_PIN = 0x06;
    private static final byte CMD_RESET = 0x07;
    private static final byte CMD_GET_NEXT_ASSERTION = 0x08;
    private static final byte CMD_CREDENTIAL_MANAGEMENT_PRE = 0x41;

    private final Version version;
    private final Backend<?> backend;

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

    public Ctap2Session(SmartCardConnection connection) throws IOException, ApplicationNotAvailableException {
        SmartCardProtocol protocol = new SmartCardProtocol(connection);
        protocol.select(AppId.FIDO);
        // it is not possible to get the applet version over NFC/CCID in CTAP2.0
        version = new Version(0, 0, 0);
        backend = new Backend<SmartCardProtocol>(protocol) {
            @Override
            byte[] sendCbor(byte[] data, @Nullable CommandState state) throws IOException, CommandException {
                //Cancellation is not implemented for NFC, and most likely not needed.
                return delegate.sendAndReceive(new Apdu(0x80, NFCCTAP_MSG, 0x00, 0x00, data));
            }
        };
        Logger.debug(logger, "Ctap2Session session initialized for connection={}",
                connection.getClass().getSimpleName());
    }

    public Ctap2Session(FidoConnection connection) throws IOException {
        FidoProtocol protocol = new FidoProtocol(connection);
        version = protocol.getVersion();
        backend = new Backend<FidoProtocol>(protocol) {
            @Override
            byte[] sendCbor(byte[] data, @Nullable CommandState state) throws IOException {
                return delegate.sendAndReceive(FidoProtocol.CTAPHID_CBOR, data, state);
            }
        };
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

    private Map<Integer, ?> sendCbor(byte command, @Nullable Object payload, @Nullable CommandState state) throws IOException, CommandException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(command);
        if (payload != null) {
            Cbor.encodeTo(baos, payload);
        }
        byte[] response = backend.sendCbor(baos.toByteArray(), state);
        byte status = response[0];
        if (status != 0x00) {
            throw new CtapException(status);
        }
        if (response.length == 1) {
            return Collections.emptyMap();  // Empty response
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
     * Read CTAP information from a Yubikey.
     *
     * @return an InfoData object with information about the YubiKey
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     */
    public InfoData getInfo() throws IOException, CommandException {
        return InfoData.fromData(Objects.requireNonNull(sendCbor(CMD_GET_INFO, null, null)));
    }

    Map<Integer, ?> clientPin(
            int version,
            byte subCommand,
            @Nullable Map<Integer, ?> keyAgreement,
            @Nullable byte[] pinUvAuthParam,
            @Nullable byte[] newPinEnc,
            @Nullable byte[] pinHashEnc
    ) throws IOException, CommandException {
        return sendCbor(CMD_CLIENT_PIN, args(version, subCommand, keyAgreement, pinUvAuthParam, newPinEnc, pinHashEnc), null);
    }

    Map<Integer, ?> credentialManagement(
            byte subCommand,
            @Nullable Map<?, ?> subCommandParams,
            int pinUvAuthProtocol,
            @Nullable byte[] pinUvAuthParam
    ) throws IOException, CommandException {
        //TODO: Figure out when to use the PRE command byte, and when to use the final one.
        return sendCbor(CMD_CREDENTIAL_MANAGEMENT_PRE, args(subCommand, subCommandParams, pinUvAuthParam != null ? pinUvAuthProtocol : null, pinUvAuthParam), null);
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
     */
    public void reset(@Nullable CommandState state) throws IOException, CommandException {
        sendCbor(CMD_RESET, null, state);
    }

    /**
     * This method is invoked by the host to request generation of a new credential in the authenticator.
     *
     * @param clientDataHash    a SHA-256 hash of the clientDataJson
     * @param rp                a Map containing the RpEntity data
     * @param user              a Map containing the UserEntity data
     * @param pubKeyCredParams  a List of Maps containing the supported credential algorithms
     * @param excludeList       a List of Maps of already registered credentials
     * @param extensions        a Map of CTAP extension inputs
     * @param options           a Map of CTAP options
     * @param pinUvAuthParam    a byte array derived from a pinToken
     * @param pinUvAuthProtocol the PIN protocol version used for the pinUvAuthParam
     * @param state             an optional state object to cancel a request and handle keepalive signals
     * @return a new credential
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorMakeCredential">authenticatorMakeCredential</a>
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
            int pinUvAuthProtocol,
            @Nullable CommandState state
    ) throws IOException, CommandException {
        Logger.debug(logger, "makeCredential for rp={},user={},clientDataHash={}," +
                        "pubKeyCredParams={},excludeList={},extensions={},options={}," +
                        "pinUvAuthParam={},pinUvAuthProtocol={},state={}",
                rp, user, clientDataHash, pubKeyCredParams, excludeList, extensions, options,
                pinUvAuthParam, pinUvAuthProtocol, state);

        CredentialData credentialData = CredentialData.fromData(Objects.requireNonNull(
                sendCbor(CMD_MAKE_CREDENTIAL, args(
                        clientDataHash,
                        rp,
                        user,
                        pubKeyCredParams,
                        excludeList,
                        extensions,
                        options,
                        pinUvAuthParam,
                        pinUvAuthParam == null ? null : pinUvAuthProtocol
                ), state)));
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
     * @see <a href="https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#authenticatorGetAssertion">authenticatorGetAssertion</a>
     */
    public List<AssertionData> getAssertions(
            String rpId,
            byte[] clientDataHash,
            @Nullable List<Map<String, ?>> allowList,
            @Nullable Map<String, ?> extensions,
            @Nullable Map<String, ?> options,
            @Nullable byte[] pinUvAuthParam,
            int pinUvAuthProtocol,
            @Nullable CommandState state
    ) throws IOException, CommandException {
        Logger.debug(logger, "getAssertions for rpId={},clientDataHash={}," +
                        "allowList={},extensions={},options={},pinUvAuthParam={}," +
                        "pinUvAuthProtocol={},state={}",
                rpId, clientDataHash, allowList, extensions, options, pinUvAuthParam, pinUvAuthProtocol);
        Map<Integer, ?> assertion = Objects.requireNonNull(sendCbor(CMD_GET_ASSERTION, args(
                rpId,
                clientDataHash,
                allowList,
                extensions,
                options,
                pinUvAuthParam,
                pinUvAuthParam == null ? null : pinUvAuthProtocol
        ), state));
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

    @Override
    public void close() throws IOException {
        backend.close();
    }

    @Override
    public Version getVersion() {
        return version;
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
        private final Map<String, Object> certifications;
        @Nullable
        private final Integer remainingDiscoverableCredentials;
        private final List<Integer> vendorPrototypeConfigCommands;

        private InfoData(
                List<String> versions,
                List<String> extensions,
                byte[] aaguid,
                Map<String, Object> options,
                int maxMsgSize,
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
                Map<String, Object> certifications,
                @Nullable Integer remainingDiscoverableCredentials,
                List<Integer> vendorPrototypeConfigCommands) {
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
                    data.containsKey(RESULT_MAX_CREDS_IN_LIST)
                            ? (Integer) data.get(RESULT_MAX_CREDS_IN_LIST)
                            : null,
                    data.containsKey(RESULT_MAX_CRED_ID_LENGTH)
                            ? (Integer) data.get(RESULT_MAX_CRED_ID_LENGTH)
                            : null,
                    data.containsKey(RESULT_TRANSPORTS)
                            ? (List<String>) data.get(RESULT_TRANSPORTS)
                            : Collections.emptyList(),
                    data.containsKey(RESULT_ALGORITHMS)
                            ? (List<PublicKeyCredentialParameters>) data.get(RESULT_ALGORITHMS)
                            : null,
                    data.containsKey(RESULT_MAX_SERIALIZED_LARGE_BLOB_ARRAY)
                            ? (Integer) data.get(RESULT_MAX_SERIALIZED_LARGE_BLOB_ARRAY)
                            : null,
                    data.containsKey(RESULT_FORCE_PIN_CHANGE)
                            ? (Boolean) data.get(RESULT_FORCE_PIN_CHANGE)
                            : null,
                    data.containsKey(RESULT_MIN_PIN_LENGTH)
                            ? (Integer) data.get(RESULT_MIN_PIN_LENGTH)
                            : null,
                    data.containsKey(RESULT_FIRMWARE_VERSION)
                            ? (Integer) data.get(RESULT_FIRMWARE_VERSION)
                            : null,
                    data.containsKey(RESULT_MAX_CRED_BLOB_LENGTH)
                            ? (Integer) data.get(RESULT_MAX_CRED_BLOB_LENGTH)
                            : null,
                    data.containsKey(RESULT_MAX_RPID_FOR_SET_MIN_PIN_LENGTH)
                            ? (Integer) data.get(RESULT_MAX_RPID_FOR_SET_MIN_PIN_LENGTH)
                            : null,
                    data.containsKey(RESULT_PREFERRED_PLATFORM_UV_ATTEMPTS)
                            ? (Integer) data.get(RESULT_PREFERRED_PLATFORM_UV_ATTEMPTS)
                            : null,
                    data.containsKey(RESULT_UV_MODALITY)
                            ? (Integer) data.get(RESULT_UV_MODALITY)
                            : null,
                    data.containsKey(RESULT_CERTIFICATIONS)
                            ? (Map<String, Object>) data.get(RESULT_CERTIFICATIONS)
                            : Collections.emptyMap(),
                    data.containsKey(RESULT_REMAINING_DISCOVERABLE_CREDENTIALS)
                            ? (Integer) data.get(RESULT_REMAINING_DISCOVERABLE_CREDENTIALS)
                            : null,
                    data.containsKey(RESULT_VENDOR_PROTOTYPE_CONFIG_COMMANDS)
                            ? (List<Integer>) data.get(RESULT_VENDOR_PROTOTYPE_CONFIG_COMMANDS)
                            : Collections.emptyList()
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
        public List<Integer> getPinUvAuthProtocols() {
            return pinUvAuthProtocols;
        }

        @Nullable
        Integer getMaxCredentialCountInList() {
            return maxCredentialCountInList;
        }

        @Nullable
        Integer getMaxCredentialIdLength() {
            return maxCredentialIdLength;
        }

        /**
         * Get a list of the supported transports.
         *
         * @return a list of supported transports.
         */
        public List<String> getTransports() {
            return transports;
        }

        @Nullable
        public List<PublicKeyCredentialParameters> getAlgorithms() {
            return algorithms;
        }

        @Nullable
        public Integer getMaxSerializedLargeBlobArray() {
            return maxSerializedLargeBlobArray;
        }

        @Nullable
        public Boolean getForcePINChange() {
            return forcePINChange;
        }

        @Nullable
        public Integer getMinPINLength() {
            return minPINLength;
        }

        @Nullable
        Integer getFirmwareVersion() {
            return firmwareVersion;
        }

        @Nullable
        public Integer getMaxCredBlobLength() {
            return maxCredBlobLength;
        }

        @Nullable
        public Integer getMaxRPIDsForSetMinPINLength() {
            return maxRPIDsForSetMinPINLength;
        }

        @Nullable
        public Integer getPreferredPlatformUvAttempts() {
            return preferredPlatformUvAttempts;
        }

        @Nullable
        public Integer getUvModality() {
            return uvModality;
        }

        public final Map<String, Object> getCertifications() {
            return certifications;
        }

        @Nullable
        public Integer getRemainingDiscoverableCredentials() {
            return remainingDiscoverableCredentials;
        }

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
        private final static int RESULT_FMT = 1;
        private final static int RESULT_AUTH_DATA = 2;
        private final static int RESULT_ATT_STMT = 3;

        private final String format;
        private final byte[] authenticatorData;
        private final Map<String, ?> attestationStatement;

        private CredentialData(String format, byte[] authenticatorData, Map<String, ?> attestationStatement) {
            this.format = format;
            this.authenticatorData = authenticatorData;
            this.attestationStatement = attestationStatement;
        }

        @SuppressWarnings("unchecked")
        private static CredentialData fromData(Map<Integer, ?> data) {
            return new CredentialData(
                    Objects.requireNonNull((String) data.get(RESULT_FMT)),
                    Objects.requireNonNull((byte[]) data.get(RESULT_AUTH_DATA)),
                    Objects.requireNonNull((Map<String, ?>) data.get(RESULT_ATT_STMT))
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
/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.*;
import com.yubico.yubikit.core.otp.ChecksumUtils;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.otp.OtpProtocol;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;

import javax.annotation.Nullable;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Application to use and configure the OTP application of the YubiKey.
 * This applications supports configuration of the two YubiKey "OTP slots" which are typically activated by pressing
 * the capacitive sensor on the YubiKey for either a short or long press.
 * <p>
 * Each slot can be configured with one of the following types of credentials:
 * - YubiOTP - a Yubico OTP (One Time Password) credential.
 * - OATH-HOTP - a counter based (HOTP) OATH OTP credential (see https://tools.ietf.org/html/rfc4226).
 * - Static Password - a static (non-changing) password.
 * - Challenge-Response - a HMAC-SHA1 key which can be accessed programmatically.
 * <p>
 * Additionally for NFC enabled YubiKeys, one slot can be configured to be output over NDEF as part of a URL payload.
 */
public class YubiOtpSession implements Closeable {
    private static final byte[] AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01};
    private static final byte[] MGMT_AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17};
    private static final byte INS_CONFIG = 0x01;

    private static final int HMAC_CHALLENGE_SIZE = 64;
    private static final int HMAC_RESPONSE_SIZE = 20;

    private static final byte CMD_CONFIG_1 = 0x1;
    private static final byte CMD_NAV = 0x2;
    private static final byte CMD_CONFIG_2 = 0x3;
    private static final byte CMD_UPDATE_1 = 0x4;
    private static final byte CMD_UPDATE_2 = 0x5;
    private static final byte CMD_SWAP = 0x6;
    private static final byte CMD_NDEF_1 = 0x8;
    private static final byte CMD_NDEF_2 = 0x9;
    private static final byte CMD_DEVICE_SERIAL = 0x10;
    private static final byte CMD_SCAN_MAP = 0x12;
    private static final byte CMD_CHALLENGE_OTP_1 = 0x20;
    private static final byte CMD_CHALLENGE_OTP_2 = 0x28;
    private static final byte CMD_CHALLENGE_HMAC_1 = 0x30;
    private static final byte CMD_CHALLENGE_HMAC_2 = 0x38;

    private final Backend<?> backend;

    /**
     * Connect to a YubiKey session, and create a new instance of {@link YubiOtpSession}.
     *
     * @param session A YubiKey session to use
     * @return a new YubiKey Configuration Application instance
     * @throws IOException                      in case of a communication error
     * @throws ApplicationNotAvailableException if the application is not available
     */
    public static YubiOtpSession create(YubiKeyDevice session) throws IOException, ApplicationNotAvailableException {
        if (session.supportsConnection(OtpConnection.class)) {
            return new YubiOtpSession(session.openConnection(OtpConnection.class));
        } else if (session.supportsConnection(SmartCardConnection.class)) {
            return new YubiOtpSession(session.openConnection(SmartCardConnection.class));
        }
        throw new ApplicationNotAvailableException("Session does not support any compatible connection type");
    }

    /**
     * Create new instance of {@link YubiOtpSession} using an {@link SmartCardConnection}.
     * NOTE: Not all functionality is available over all interfaces. Over USB, some functionality may be blocked when
     * not using an OtpConnection.
     *
     * @param connection an Iso7816Connection with a YubiKey
     * @throws IOException                      in case of connection error
     * @throws ApplicationNotAvailableException if the application is missing or disabled
     */
    public YubiOtpSession(SmartCardConnection connection) throws IOException, ApplicationNotAvailableException {
        Version version = null;
        SmartCardProtocol protocol = new SmartCardProtocol(connection);

        if (connection.getInterface() == Interface.NFC) {
            // If available, this is more reliable than status.getVersion() over NFC
            try {
                byte[] response = protocol.select(MGMT_AID);
                version = Version.parse(new String(response, StandardCharsets.UTF_8));
            } catch (ApplicationNotAvailableException e) {
                // NEO: version will be populated further down.
            }
        }

        byte[] statusBytes = protocol.select(AID);
        if (version == null) {
            // We didn't get a version above, get it from the status struct.
            version = Version.parse(statusBytes);
        }

        protocol.enableTouchWorkaround(version);

        backend = new Backend<SmartCardProtocol>(protocol, version, parseConfigState(version, statusBytes)) {
            // 5.0.0-5.2.5 have an issue with status over NFC
            private final boolean dummyStatus = connection.getInterface() == Interface.NFC && version.isAtLeast(5, 0, 0) && version.isLessThan(5, 2, 5);

            {
                if (dummyStatus) { // We can't read the status, so use a dummy with both slots marked as configured.
                    configState = new ConfigState(version, (short) 3);
                }
            }

            @Override
            void writeConfig(byte slot, byte[] data) throws IOException, CommandException {
                byte[] status = delegate.sendAndReceive(new Apdu(0, INS_CONFIG, slot, 0, data));
                if (!dummyStatus) {
                    configState = parseConfigState(this.version, status);
                }
            }

            @Override
            byte[] sendAndReceive(byte slot, byte[] data, int expectedResponseLength, @Nullable CommandState state) throws IOException, CommandException {
                byte[] response = delegate.sendAndReceive(new Apdu(0, INS_CONFIG, slot, 0, data));
                if (expectedResponseLength != response.length) {
                    throw new BadResponseException("Unexpected response length");
                }
                return response;
            }
        };
    }

    /**
     * Create new instance of {@link YubiOtpSession} using an {@link OtpConnection}.
     *
     * @param connection an OtpConnection with YubiKey
     * @throws IOException in case of connection error
     */
    public YubiOtpSession(OtpConnection connection) throws IOException {
        OtpProtocol protocol = new OtpProtocol(connection);
        byte[] statusBytes = protocol.readStatus();
        Version version = Version.parse(statusBytes);
        backend = new Backend<OtpProtocol>(protocol, version, parseConfigState(version, statusBytes)) {
            @Override
            void writeConfig(byte slot, byte[] data) throws IOException, CommandException {
                configState = parseConfigState(version, delegate.sendAndReceive(slot, data, null));
            }

            @Override
            byte[] sendAndReceive(byte slot, byte[] data, int expectedResponseLength, @Nullable CommandState state) throws IOException, CommandException {
                byte[] response = delegate.sendAndReceive(slot, data, state);
                if (ChecksumUtils.checkCrc(response, expectedResponseLength + 2)) {
                    return Arrays.copyOf(response, expectedResponseLength);
                }
                throw new IOException("Invalid CRC");
            }
        };
    }

    @Override
    public void close() throws IOException {
        backend.close();
    }

    /**
     * Get the configuration state of the application.
     *
     * @return the current configuration state of the two slots.
     */
    public ConfigState getConfigState() {
        return backend.configState;
    }

    /**
     * Get the firmware version of the YubiKey
     *
     * @return Yubikey firmware version
     */
    public Version getVersion() {
        return backend.version;
    }

    /**
     * Get the serial number of the YubiKey.
     * Note that the EXTFLAG_SERIAL_API_VISIBLE flag must be set for this command to work.
     *
     * @return the serial number
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public int getSerialNumber() throws IOException, CommandException {
        return ByteBuffer.wrap(backend.sendAndReceive(CMD_DEVICE_SERIAL, new byte[0], 4, null)).getInt();
    }

    /**
     * Swaps the two slot configurations with each other.
     *
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void swapSlots() throws IOException, CommandException {
        if (backend.version.isLessThan(2, 3, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.3+");
        }

        writeConfig(CMD_SWAP, new byte[0], null);
    }

    /**
     * Delete the contents of a slot.
     *
     * @param slot       the slot to delete
     * @param curAccCode the currently set access code, if needed
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void deleteSlot(Slot slot, @Nullable byte[] curAccCode) throws IOException, CommandException {
        writeConfig(
                slot.map(CMD_CONFIG_1, CMD_CONFIG_2),
                new byte[ConfigUtils.CONFIG_SIZE],
                curAccCode
        );
    }

    /**
     * Write configuration to a slot, overwriting previous values.
     * This command allows full control over the EXT, TKT and CFG flags to set, the access code to use, and the access code to set.
     *
     * @param slot       the slot to write to
     * @param fixed      the fixed field of the configuration
     * @param uid        the uid field of the configuration
     * @param key        the key field of the configuration
     * @param extFlags   the EXT_FLAGs to set
     * @param tktFlags   the TKT_FLAGs to set
     * @param cfgFlags   the CFG_FLAGs to set
     * @param accCode    the access code to set
     * @param curAccCode the current access code, if needed
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void putConfiguration(Slot slot, byte[] fixed, byte[] uid, byte[] key, byte extFlags, byte tktFlags, byte cfgFlags, @Nullable byte[] accCode, @Nullable byte[] curAccCode) throws IOException, CommandException {
        writeConfig(
                slot.map(CMD_CONFIG_1, CMD_CONFIG_2),
                ConfigUtils.buildConfig(fixed, uid, key, extFlags, tktFlags, cfgFlags, accCode),
                curAccCode
        );
    }

    /**
     * Write a configuration to a slot, overwriting previous configuration (if present).
     *
     * @param slot          the slot to write to
     * @param configuration the new configuration to write
     * @param accCode       the access code to set (or null, to not set an access code)
     * @param curAccCode    the current access code, if one is set for the target slot
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void putConfiguration(Slot slot, SlotConfiguration configuration, @Nullable byte[] accCode, @Nullable byte[] curAccCode) throws IOException, CommandException {
        if (backend.version.compareTo(configuration.getMinimumVersion()) < 0) {
            throw new NotSupportedOperation("This configuration type requires YubiKey " + configuration.getMinimumVersion() + "or later");
        }
        writeConfig(
                slot.map(CMD_CONFIG_1, CMD_CONFIG_2),
                configuration.getConfig(accCode),
                curAccCode
        );
    }

    /**
     * Update an already programmed slot with new configuration.
     * <p>
     * Note that the EXTFLAG_ALLOW_UPDATE must have been previously set in the configuration to allow update, and must
     * again be set in this call to allow further updates.
     *
     * @param slot       the slot to update
     * @param extFlags   the updated EXT_FLAGs to set
     * @param tktFlags   the updated TKT_FLAGs to set
     * @param cfgFlags   the updated CFG_FLAGs to set
     * @param accCode    the access code to set
     * @param curAccCode the current access code, if needed
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void updateConfiguration(Slot slot, byte extFlags, byte tktFlags, byte cfgFlags, @Nullable byte[] accCode, @Nullable byte[] curAccCode) throws IOException, CommandException {
        writeConfig(
                slot.map(CMD_UPDATE_1, CMD_UPDATE_2),
                ConfigUtils.buildUpdateConfig(extFlags, tktFlags, cfgFlags, accCode),
                curAccCode
        );
    }

    /**
     * Configure the NFC NDEF payload, and which slot to use.
     *
     * @param slot       the YubiKey slot to append to the uri payload
     * @param uri        the URI prefix (if null, the default "https://my.yubico.com/yk/#" will be used)
     * @param curAccCode the current access code, if needed
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void setNdefConfiguration(Slot slot, @Nullable String uri, @Nullable byte[] curAccCode) throws IOException, CommandException {
        writeConfig(
                slot.map(CMD_NDEF_1, CMD_NDEF_2),
                ConfigUtils.buildNdefConfig(uri),
                curAccCode
        );
    }


    /**
     * Calculates HMAC-SHA1 on given challenge (using secret that configured/programmed on YubiKey)
     *
     * @param slot      the slot on YubiKey that configured with challenge response secret
     * @param challenge generated challenge that will be sent
     * @param state     if false, the command will be aborted in case the credential requires user touch
     * @return response on challenge returned from YubiKey
     * @throws IOException      in case of communication error, or no key configured in slot
     * @throws CommandException in case of an error response from the YubiKey
     */
    public byte[] calculateHmacSha1(Slot slot, byte[] challenge, @Nullable CommandState state) throws IOException, CommandException {
        // works on version above 2.2
        if (backend.version.isLessThan(2, 2, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.2+");
        }

        // Pad challenge with byte different from last.
        byte[] padded = new byte[HMAC_CHALLENGE_SIZE];
        Arrays.fill(padded, (byte) (challenge[challenge.length - 1] == 0 ? 1 : 0));
        System.arraycopy(challenge, 0, padded, 0, challenge.length);

        // response for HMAC-SHA1 challenge response is always 20 bytes
        return backend.sendAndReceive(
                slot.map(CMD_CHALLENGE_HMAC_1, CMD_CHALLENGE_HMAC_2),
                padded,
                HMAC_RESPONSE_SIZE,
                state
        );
    }

    private void writeConfig(byte commandSlot, byte[] config, @Nullable byte[] curAccCode) throws IOException, CommandException {
        backend.writeConfig(
                commandSlot,
                ByteBuffer.allocate(config.length + ConfigUtils.ACC_CODE_SIZE)
                        .put(config)
                        .put(curAccCode == null ? new byte[ConfigUtils.ACC_CODE_SIZE] : curAccCode)
                        .array()
        );
    }

    private static ConfigState parseConfigState(Version version, byte[] status) {
        return new ConfigState(version, ByteBuffer.wrap(status, 4, 2).order(ByteOrder.LITTLE_ENDIAN).getShort());
    }

    private static abstract class Backend<T extends Closeable> implements Closeable {
        protected final T delegate;
        protected final Version version;
        protected ConfigState configState;

        private Backend(T delegate, Version version, ConfigState configState) {
            this.version = version;
            this.delegate = delegate;
            this.configState = configState;
        }

        abstract void writeConfig(byte slot, byte[] data) throws IOException, CommandException;

        abstract byte[] sendAndReceive(byte slot, byte[] data, int expectedResponseLength, @Nullable CommandState state) throws IOException, CommandException;

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
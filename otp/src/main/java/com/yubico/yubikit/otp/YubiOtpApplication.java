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

package com.yubico.yubikit.otp;

import com.yubico.yubikit.core.YubiKeySession;
import com.yubico.yubikit.core.ApplicationNotAvailableException;
import com.yubico.yubikit.core.BadResponseException;
import com.yubico.yubikit.core.CommandException;
import com.yubico.yubikit.core.NotSupportedOperation;
import com.yubico.yubikit.core.otp.ChecksumUtils;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.otp.OtpProtocol;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.CommandState;
import com.yubico.yubikit.core.Interface;
import com.yubico.yubikit.core.Version;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import javax.annotation.Nullable;

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
public class YubiOtpApplication implements Closeable {
    private static final byte INS_CONFIG = (byte) 0x01;
    private static final byte[] AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01};
    private static final byte[] MGMT_AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17};

    private static final int SCAN_CODES_SIZE = Config.FIXED_SIZE + Config.UID_SIZE + Config.KEY_SIZE;

    private static final int HMAC_KEY_SIZE = 20;      // Size of OATH-HOTP key (key field + first 4 of UID field)
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

    private final Version version;
    private final Backend<?> backend;

    private ConfigState configState;

    /**
     * Connect to a YubiKey session, and create a new instance of {@link YubiOtpApplication}.
     *
     * @param session A YubiKey session to use
     * @return a new YubiKey Configuration Application instance
     * @throws IOException                      in case of a communication error
     * @throws ApplicationNotAvailableException if the application is not available
     */
    public static YubiOtpApplication create(YubiKeySession session) throws IOException, ApplicationNotAvailableException {
        if (session.supportsConnection(OtpConnection.class)) {
            return new YubiOtpApplication(session.openConnection(OtpConnection.class));
        } else if (session.supportsConnection(SmartCardConnection.class)) {
            return new YubiOtpApplication(session.openConnection(SmartCardConnection.class));
        }
        throw new ApplicationNotAvailableException("Session does not support any compatible connection type");
    }

    /**
     * Create new instance of {@link YubiOtpApplication} using an {@link SmartCardConnection}.
     * NOTE: Not all functionality is available over all interfaces. Over USB, some functionality may be blocked when
     * not using an OtpConnection.
     *
     * @param connection an Iso7816Connection with a YubiKey
     * @throws IOException                      in case of connection error
     * @throws ApplicationNotAvailableException if the application is missing or disabled
     */
    public YubiOtpApplication(SmartCardConnection connection) throws IOException, ApplicationNotAvailableException {
        Version version = null;
        if (connection.getInterface() == Interface.NFC) {
            // If available, this is more reliable than status.getVersion() over NFC
            try {
                SmartCardProtocol mgmtApplication = new SmartCardProtocol(MGMT_AID, connection);
                byte[] response = mgmtApplication.select();
                version = Version.parse(new String(response));
            } catch (ApplicationNotAvailableException e) {
                // NEO: version will be populated further down.
            }
        }

        SmartCardProtocol protocol = new SmartCardProtocol(AID, connection);
        byte[] statusBytes = protocol.select();
        if (version == null) {
            // We didn't get a version above, get it from the status struct.
            version = Version.parse(statusBytes);
        }
        this.version = version;
        configState = parseConfigState(version, statusBytes);
        protocol.enableTouchWorkaround(version);
        backend = new Backend<SmartCardProtocol>(protocol) {
            @Override
            byte[] writeConfig(byte slot, byte[] data) throws IOException, CommandException {
                return delegate.sendAndReceive(new Apdu(0, INS_CONFIG, slot, 0, data));
            }

            @Override
            byte[] transceive(byte slot, byte[] data, int expectedResponseLength, @Nullable CommandState state) throws IOException, CommandException {
                byte[] response = delegate.sendAndReceive(new Apdu(0, INS_CONFIG, slot, 0, data));
                if (expectedResponseLength != response.length) {
                    throw new BadResponseException("Unexpected response length");
                }
                return response;
            }
        };
    }

    /**
     * Create new instance of {@link YubiOtpApplication} using an {@link OtpConnection}.
     *
     * @param connection an OtpConnection with YubiKey
     * @throws IOException in case of connection error
     */
    public YubiOtpApplication(OtpConnection connection) throws IOException {
        OtpProtocol protocol = new OtpProtocol(connection);
        byte[] statusBytes = protocol.readStatus();
        version = Version.parse(statusBytes);
        configState = parseConfigState(version, statusBytes);
        backend = new Backend<OtpProtocol>(protocol) {
            @Override
            byte[] writeConfig(byte slot, byte[] data) throws IOException, CommandException {
                return delegate.sendAndReceive(slot, data, null);
            }

            @Override
            byte[] transceive(byte slot, byte[] data, int expectedResponseLength, @Nullable CommandState state) throws IOException, CommandException {
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
    public ConfigState getStatus() {
        return configState;
    }

    /**
     * Get the firmware version of the YubiKey
     *
     * @return Yubikey firmware version
     */
    public Version getVersion() {
        return version;
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
        return ByteBuffer.wrap(backend.transceive(CMD_DEVICE_SERIAL, new byte[0], 4, null)).getInt();
    }

    /**
     * Swaps the two slot configurations with each other.
     *
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void swapSlots() throws IOException, CommandException {
        if (version.isLessThan(2, 3, 0)) {
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
                new byte[Config.CONFIG_SIZE],
                curAccCode
        );
    }

    /**
     * Write configuration to a slot, overwriting previous values.
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
                Config.buildConfig(fixed, uid, key, extFlags, tktFlags, cfgFlags, accCode),
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
                Config.buildUpdateConfig(extFlags, tktFlags, cfgFlags, accCode),
                curAccCode
        );
    }

    /**
     * Configure the NFC NDEF payload, and which slot to use.
     *
     * @param slot       the YubiKey slot to append to the uri payload
     * @param uri        the URI prefix
     * @param curAccCode the current access code, if needed
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void setNdefConfiguration(Slot slot, String uri, @Nullable byte[] curAccCode) throws IOException, CommandException {
        writeConfig(slot.map(CMD_NDEF_1, CMD_NDEF_2), Config.buildNdefConfig(uri), curAccCode);
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
        if (version.isLessThan(2, 2, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.2+");
        }

        // Pad challenge with byte different from last.
        byte[] padded = new byte[HMAC_CHALLENGE_SIZE];
        Arrays.fill(padded, (byte) (challenge[challenge.length - 1] == 0 ? 1 : 0));
        System.arraycopy(challenge, 0, padded, 0, challenge.length);

        // response for HMAC-SHA1 challenge response is always 20 bytes
        return backend.transceive(
                slot.map(CMD_CHALLENGE_HMAC_1, CMD_CHALLENGE_HMAC_2),
                padded,
                HMAC_RESPONSE_SIZE,
                state
        );
    }

    /**
     * Configures HMAC-SHA1 challenge response secret on YubiKey
     * ({@link #calculateHmacSha1(Slot, byte[], CommandState)} how to use it after configuration)
     *
     * @param slot         the slot on YubiKey that will be configured with challenge response
     * @param secret       the 20 bytes HMAC key to store
     * @param requireTouch whether or not the YubiKey should require touch to use this key
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void putHmacSha1Key(Slot slot, byte[] secret, boolean requireTouch) throws IOException, CommandException {
        if (version.isLessThan(2, 2, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.2+");
        }
        if (secret.length > HMAC_KEY_SIZE) {
            throw new NotSupportedOperation("key lengths >20 bytes is not supported");
        }

        // Secret is packed into key and uid
        byte[] key = new byte[Config.KEY_SIZE];
        byte[] uid = new byte[Config.UID_SIZE];
        ByteBuffer.wrap(ByteBuffer.allocate(Config.KEY_SIZE + Config.UID_SIZE).put(secret).array()).get(key).get(uid);

        byte cfgFlags = Config.CFGFLAG_CHAL_HMAC | Config.CFGFLAG_HMAC_LT64;
        if (requireTouch) {
            cfgFlags |= Config.CFGFLAG_CHAL_BTN_TRIG;
        }

        putConfiguration(
                slot,
                new byte[0],
                uid,
                key,
                (byte) (Config.EXTFLAG_ALLOW_UPDATE | Config.EXTFLAG_SERIAL_API_VISIBLE),
                Config.TKTFLAG_CHAL_RESP,
                cfgFlags,
                null,
                null
        );
    }

    /**
     * Configures YubiKey to return static password on touch
     *
     * @param slot      the slot on YubiKey that will be configured with provided password (One - short touch, Two - long touch)
     * @param scanCodes the password to store on YubiKey as an array of keyboard scan codes.
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void putStaticPassword(Slot slot, byte[] scanCodes) throws IOException, CommandException {
        if (version.isLessThan(2, 2, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.2+");
        }
        if (scanCodes.length > SCAN_CODES_SIZE) {
            throw new NotSupportedOperation("Password is too long");
        }

        // Scan codes are packed into fixed, uid, and key, and zero padded.
        byte[] fixed = new byte[Config.FIXED_SIZE];
        byte[] uid = new byte[Config.UID_SIZE];
        byte[] key = new byte[Config.KEY_SIZE];
        ByteBuffer.wrap(ByteBuffer.allocate(SCAN_CODES_SIZE).put(scanCodes).array()).get(fixed).get(uid).get(key);
        putConfiguration(
                slot,
                fixed,
                uid,
                key,
                (byte) (Config.EXTFLAG_ALLOW_UPDATE | Config.EXTFLAG_SERIAL_API_VISIBLE),
                Config.TKTFLAG_APPEND_CR,
                Config.CFGFLAG_SHORT_TICKET,
                null,
                null
        );
    }


    /**
     * Configures the YubiKey to return YubiOTP (one-time password) on touch
     *
     * @param slot      the slot on YubiKey that will be configured with OTP (One - short touch, Two - long touch)
     * @param publicId  public id
     * @param privateId private id
     * @param key       the secret key to store on YubiKey
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void putYubiOtpKey(Slot slot, byte[] publicId, byte[] privateId, byte[] key) throws IOException, CommandException {
        putConfiguration(
                slot,
                publicId,
                privateId,
                key,
                (byte) (Config.EXTFLAG_ALLOW_UPDATE | Config.EXTFLAG_SERIAL_API_VISIBLE),
                Config.TKTFLAG_APPEND_CR,
                (byte) 0,
                null,
                null
        );
    }

    /**
     * Configures the YubiKey to return an OATH-HOTP code on touch
     *
     * @param slot        the slot on YubiKey that will be configured (slot 1 - short touch, slot 2 - long touch)
     * @param secret      the shared secret for the OATH-TOTP credential
     * @param hotp8digits if true will generate 8 digits code (default is 6)
     * @param imf         initial moving factor (counter value) for the credential, must be a multiple of 16 (default is 0)
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void putOathHotpKey(Slot slot, byte[] secret, boolean hotp8digits, int imf) throws IOException, CommandException {
        if (version.isLessThan(2, 1, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.1+");
        }
        if (secret.length > HMAC_KEY_SIZE) {
            throw new NotSupportedOperation("key lengths >20 bytes is not supported");
        }

        // Secret is packed into key and uid
        byte[] uid = new byte[Config.UID_SIZE];
        byte[] key = new byte[Config.KEY_SIZE];
        ByteBuffer.wrap(ByteBuffer.allocate(Config.KEY_SIZE + Config.UID_SIZE).put(secret).array()).get(key).get(uid);
        // IMF is packed into last 2 bytes of uid
        ByteBuffer.wrap(uid, 4, 2).putShort((short) (imf / 16));

        byte cfgFlags = 0;
        if (hotp8digits) {
            cfgFlags |= Config.CFGFLAG_OATH_HOTP8;
        }

        putConfiguration(
                slot,
                new byte[0],
                uid,
                key,
                (byte) (Config.EXTFLAG_ALLOW_UPDATE | Config.EXTFLAG_SERIAL_API_VISIBLE),
                (byte) (Config.TKTFLAG_OATH_HOTP | Config.TKTFLAG_APPEND_CR),
                cfgFlags,
                null,
                null
        );
    }

    private void writeConfig(byte commandSlot, byte[] config, @Nullable byte[] curAccCode) throws IOException, CommandException {
        configState = parseConfigState(version, backend.writeConfig(
                commandSlot,
                ByteBuffer.allocate(config.length + Config.ACC_CODE_SIZE)
                        .put(config)
                        .put(curAccCode == null ? new byte[Config.ACC_CODE_SIZE] : curAccCode)
                        .array()
        ));
    }

    private static ConfigState parseConfigState(Version version, byte[] status) {
        return new ConfigState(version, ByteBuffer.wrap(status, 4, 2).order(ByteOrder.LITTLE_ENDIAN).getShort());
    }

    private static abstract class Backend<T extends Closeable> implements Closeable {
        protected final T delegate;

        private Backend(T delegate) {
            this.delegate = delegate;
        }

        abstract byte[] writeConfig(byte slot, byte[] data) throws IOException, CommandException;

        abstract byte[] transceive(byte slot, byte[] data, int expectedResponseLength, @Nullable CommandState state) throws IOException, CommandException;

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
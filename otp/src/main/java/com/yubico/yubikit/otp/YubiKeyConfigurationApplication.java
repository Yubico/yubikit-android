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

import com.yubico.yubikit.exceptions.ApplicationNotAvailableException;
import com.yubico.yubikit.exceptions.BadResponseException;
import com.yubico.yubikit.exceptions.CommandException;
import com.yubico.yubikit.exceptions.NotSupportedOperation;
import com.yubico.yubikit.iso7816.Apdu;
import com.yubico.yubikit.iso7816.Iso7816Application;
import com.yubico.yubikit.iso7816.Iso7816Connection;
import com.yubico.yubikit.keyboard.ChecksumUtils;
import com.yubico.yubikit.keyboard.OtpApplication;
import com.yubico.yubikit.keyboard.OtpConnection;
import com.yubico.yubikit.utils.CommandState;
import com.yubico.yubikit.utils.Interface;
import com.yubico.yubikit.utils.Version;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import javax.annotation.Nullable;

/**
 * Application to use and configure the OTP application of the YubiKey.
 */
public class YubiKeyConfigurationApplication implements Closeable {
    private static final byte INS_CONFIG = (byte) 0x01;
    private static final byte[] AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01};
    private static final byte[] MGMT_AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17};

    private static final int KEY_SIZE_OATH = 20;      // Size of OATH-HOTP key (key field + first 4 of UID field)
    private static final int SCAN_CODES_SIZE = Config.FIXED_SIZE + Config.UID_SIZE + Config.KEY_SIZE;

    private final Version version;

    /**
     * Response on select of application
     */
    private ConfigState configState;

    /**
     * This applet is implemented on 2 interfaces: CCID and OTP
     */
    private final Backend<?> backend;

    /**
     * Create new instance of {@link YubiKeyConfigurationApplication} using an {@link Iso7816Connection}.
     * NOTE: Not all functionality is available over all interfaces. Over USB, some functionality may be blocked when
     * not using an OtpConnection.
     *
     * @param connection an Iso7816Connection with a YubiKey
     * @throws IOException                      in case of connection error
     * @throws ApplicationNotAvailableException if the application is missing or disabled
     */
    public YubiKeyConfigurationApplication(Iso7816Connection connection) throws IOException, ApplicationNotAvailableException {
        Version version = null;
        if (connection.getInterface() == Interface.NFC) {
            // If available, this is more reliable than status.getVersion() over NFC
            try {
                Iso7816Application mgmtApplication = new Iso7816Application(MGMT_AID, connection);
                byte[] response = mgmtApplication.select();
                version = Version.parse(new String(response));
            } catch (ApplicationNotAvailableException e) {
                // NEO: version will be populated further down.
            }
        }

        Iso7816Application ccidApplication = new Iso7816Application(AID, connection);
        byte[] statusBytes = ccidApplication.select();
        if (version == null) {
            // We didn't get a version above, get it from the status struct.
            version = Version.parse(statusBytes);
        }
        this.version = version;
        configState = parseConfigState(version, statusBytes);
        backend = new Backend<Iso7816Application>(ccidApplication) {
            @Override
            byte[] writeConfig(byte slot, byte[] data) throws IOException, CommandException {
                return delegate.sendAndReceive(new Apdu(0, INS_CONFIG, slot, 0, data));
            }

            @Override
            byte[] transceive(byte slot, byte[] data, int expectedResponseLength, @Nullable CommandState state) throws IOException, CommandException {
                byte[] response = delegate.sendAndReceive(new Apdu(0, INS_CONFIG, slot, 0, data));
                if (expectedResponseLength > 0 && expectedResponseLength != response.length) {
                    throw new BadResponseException("Unexpected response length");
                }
                return response;
            }
        };
    }

    /**
     * Create new instance of {@link YubiKeyConfigurationApplication} using an {@link OtpConnection}.
     *
     * @param connection an OtpConnection with YubiKey
     * @throws IOException in case of connection error
     */
    public YubiKeyConfigurationApplication(OtpConnection connection) throws IOException {
        OtpApplication application = new OtpApplication(connection);
        byte[] statusBytes = application.readStatus();
        version = Version.parse(statusBytes);
        configState = parseConfigState(version, statusBytes);
        backend = new Backend<OtpApplication>(application) {
            @Override
            byte[] writeConfig(byte slot, byte[] data) throws IOException, CommandException {
                return delegate.transceive(slot, data, null);
            }

            @Override
            byte[] transceive(byte slot, byte[] data, int expectedResponseLength, @Nullable CommandState state) throws IOException, CommandException {
                byte[] response = delegate.transceive(slot, data, state);
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

        // response for HMAC-SHA1 challenge response is always 20 bytes
        return backend.transceive(
                slot.map(ConfigSlot.CHALLENGE_HMAC_1, ConfigSlot.CHALLENGE_HMAC_2).value,
                challenge,
                20,
                state
        );
    }

    /**
     * Configures HMAC-SHA1 challenge response secret on YubiKey
     * (@see calculateHmacSha1() how to use it after configuration)
     *
     * @param slot         the slot on YubiKey that will be configured with challenge response
     * @param secret       the 20 bytes HMAC key to store
     * @param requireTouch whether or not the YubiKey should require touch to use this key
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void setHmacSha1Key(Slot slot, byte[] secret, boolean requireTouch) throws IOException, CommandException {
        if (version.isLessThan(2, 2, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.2+");
        }
        if (secret.length > KEY_SIZE_OATH) {
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

        writeConfiguration(
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
    public void setStaticPassword(Slot slot, byte[] scanCodes) throws IOException, CommandException {
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
        writeConfiguration(
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
     * Configures YubiKey to return YubiOTP (one-time password) on touch
     *
     * @param slot      the slot on YubiKey that will be configured with OTP (One - short touch, Two - long touch)
     * @param publicId  public id
     * @param privateId private id
     * @param key       the secret key to store on YubiKey
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void setOtpKey(Slot slot, byte[] publicId, byte[] privateId, byte[] key) throws IOException, CommandException {
        writeConfiguration(
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
     * Configures YubiKey to return HOTP
     *
     * @param slot        the slot on YubiKey that will be configured with HOTP (slot 1 - short touch, slot 2 - long touch)
     * @param secret      the 20 bytes secret for YubiKey to store
     * @param hotp8digits if true will generate 8 digits code (default is 6)
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void setHotpKey(Slot slot, byte[] secret, boolean hotp8digits) throws IOException, CommandException {
        if (version.isLessThan(2, 1, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.1+");
        }
        if (secret.length > KEY_SIZE_OATH) {
            throw new NotSupportedOperation("key lengths >20 bytes is not supported");
        }

        // Secret is packed into key and uid
        byte[] uid = new byte[Config.UID_SIZE];
        byte[] key = new byte[Config.KEY_SIZE];
        ByteBuffer.wrap(ByteBuffer.allocate(Config.UID_SIZE + Config.KEY_SIZE).put(secret).array()).get(key).get(uid);

        byte cfgFlags = 0;
        if (hotp8digits) {
            cfgFlags |= Config.CFGFLAG_OATH_HOTP8;
        }

        writeConfiguration(
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

    /**
     * Method allows to swap data between 1st and 2nd slot of the YubiKey
     *
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void swapSlots() throws IOException, CommandException {
        if (version.isLessThan(2, 3, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.3+");
        }

        backend.writeConfig(ConfigSlot.SWAP.value, new byte[0]);
    }

    /**
     * Delete the contents of a configuration slot.
     *
     * @param slot       the slot to delete
     * @param curAccCode the currently set access code, if needed
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void deleteSlot(Slot slot, @Nullable byte[] curAccCode) throws IOException, CommandException {
        writeConfig(
                slot.map(ConfigSlot.CONFIG_1, ConfigSlot.CONFIG_2),
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
    public void writeConfiguration(Slot slot, byte[] fixed, byte[] uid, byte[] key, byte extFlags, byte tktFlags, byte cfgFlags, @Nullable byte[] accCode, @Nullable byte[] curAccCode) throws IOException, CommandException {
        writeConfig(
                slot.map(ConfigSlot.CONFIG_1, ConfigSlot.CONFIG_2),
                Config.buildConfig(fixed, uid, key, extFlags, tktFlags, cfgFlags, accCode),
                curAccCode
        );
    }

    /**
     * Update an already programmed slot with new configuration.
     * <p>
     * Note that the EXTFLAG_ALLOW_UPDATE must have been previously set in the configuration to allow update.
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
                slot.map(ConfigSlot.UPDATE_1, ConfigSlot.UPDATE_2),
                Config.buildUpdateConfig(extFlags, tktFlags, cfgFlags, accCode),
                curAccCode
        );
    }

    /**
     * Configure NFC NDEF payload.
     *
     * @param slot       the YubiKey slot to append to the uri payload
     * @param uri        the URI prefix
     * @param curAccCode the current access code, if needed
     * @throws IOException      in case of communication error
     * @throws CommandException in case of an error response from the YubiKey
     */
    public void configureNdef(Slot slot, String uri, @Nullable byte[] curAccCode) throws IOException, CommandException {
        writeConfig(slot.map(ConfigSlot.NDEF_1, ConfigSlot.NDEF_2), Config.buildNdefConfig(uri), curAccCode);
    }

    private void writeConfig(ConfigSlot slot, byte[] config, @Nullable byte[] curAccCode) throws IOException, CommandException {
        configState = parseConfigState(version, backend.writeConfig(
                slot.value,
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
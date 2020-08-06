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

import com.yubico.yubikit.Interface;
import com.yubico.yubikit.Iso7816Application;
import com.yubico.yubikit.Iso7816Connection;
import com.yubico.yubikit.OtpConnection;
import com.yubico.yubikit.apdu.Apdu;
import com.yubico.yubikit.apdu.Version;
import com.yubico.yubikit.exceptions.ApduException;
import com.yubico.yubikit.exceptions.ApplicationNotFound;
import com.yubico.yubikit.exceptions.BadResponseException;
import com.yubico.yubikit.exceptions.NotSupportedOperation;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;

import javax.annotation.Nullable;

/**
 * Application to use and configure the OTP application of the YubiKey.
 */
public class YubiKeyConfigurationApplication implements Closeable {
    private static final byte INS_CONFIG = (byte) 0x01;
    private static final byte[] AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01};
    private static final byte[] MGMT_AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17};

    private static final int KEY_LENGTH = 20;

    private final Version version;

    /**
     * Response on select of application
     */
    private Status status;

    /**
     * This applet is implemented on 2 interfaces: CCID and OTP
     */
    private final Backend<?> backend;

    /**
     * Create new instance of {@link YubiKeyConfigurationApplication} using an {@link Iso7816Connection}.
     *
     * @param connection an Iso7816Connection with a YubiKey
     * @throws IOException         in case of connection error
     * @throws ApplicationNotFound if the application is missing or disabled.
     * @throws ApduException       in case of an error response from the YubiKey
     */
    public YubiKeyConfigurationApplication(Iso7816Connection connection) throws IOException, ApplicationNotFound, ApduException {
        // for configuration via USB use HID interface rather than CCID
        // bcz on YK5+ this app is disabled (or partially disabled)
        // NEO has a bug when challenge-response with touch returns 0x6985 error code
        Version version = null;
        if (connection.getInterface() == Interface.NFC) {
            // If available, this is more reliable than status.getVersion() over NFC
            try {
                Iso7816Application mgmtApplication = new Iso7816Application(MGMT_AID, connection);
                byte[] response = mgmtApplication.select();
                version = Version.parse(new String(response));
            } catch (ApduException e) {
                // NEO: version will be populated further down.
            }
        }

        Iso7816Application ccidApplication = new Iso7816Application(AID, connection);
        status = Status.parse(ccidApplication.select());
        if (version == null) {
            // We didn't get a version above, get it from the status struct.
            version = status.getVersion();
        }
        this.version = version;
        backend = new Backend<Iso7816Application>(ccidApplication) {
            @Override
            byte[] sendConfig(byte slot, byte[] data, int expectedResponseLength) throws IOException, ApduException {
                byte[] response = delegate.sendAndReceive(new Apdu(0, INS_CONFIG, slot, 0, data));
                if (expectedResponseLength > 0 && expectedResponseLength != response.length) {
                    throw new IOException("Unexpected response length");
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
        status = Status.parse(connection.readStatus());
        version = status.getVersion();
        backend = new Backend<OtpConnection>(connection) {
            @Override
            byte[] sendConfig(byte slot, byte[] data, int expectedResponseLength) throws IOException {
                byte[] response = delegate.transceive(slot, data, expectedResponseLength);
                if (expectedResponseLength > 0) {
                    return response;
                } else {
                    return delegate.readStatus();
                }
            }
        };
    }

    @Override
    public void close() throws IOException {
        backend.close();
    }

    public Status getStatus() {
        return status;
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
     * @param challenge generated challenge that will be sent
     * @param slot      the slot on YubiKey that configured with challenge response secret
     * @return response on challenge returned from YubiKey
     * @throws IOException           in case of communication error, or no key configured in slot
     * @throws ApduException         in case of an error response from the YubiKey
     * @throws NotSupportedOperation if the command is not supported for this YubiKey
     */
    public byte[] calculateHmacSha1(byte[] challenge, Slot slot) throws IOException, ApduException, NotSupportedOperation {
        // works on version above 2.2
        if (version.isLessThan(2, 2, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.2+");
        }

        YubiKeySlot ykSlot = slot.map(YubiKeySlot.CHALLENGE_HMAC_1, YubiKeySlot.CHALLENGE_HMAC_2);
        // response for HMAC-SHA1 challenge response is always 20 bytes
        return backend.sendConfig(ykSlot.value, challenge, 20);
    }

    /**
     * Configures HMAC-SHA1 challenge response secret on YubiKey
     * (@see calculateHmacSha1() how to use it after configuration)
     *
     * @param secret       the 20 bytes HMAC key to store
     * @param slot         the slot on YubiKey that will be configured with challenge response
     * @param requireTouch whether or not the YubiKey should require touch to use this key
     * @throws IOException           in case of communication error
     * @throws ApduException         in case of an error response from the YubiKey
     * @throws NotSupportedOperation if the command is not supported for this YubiKey
     * @throws BadResponseException  in case of an invalid response from the YubiKey
     */
    public void setHmacSha1ChallengeResponseSecret(byte[] secret, Slot slot, boolean requireTouch) throws IOException, NotSupportedOperation, BadResponseException, ApduException {
        if (version.isLessThan(2, 2, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.2+");
        }

        if (secret.length > KEY_LENGTH) {
            throw new NotSupportedOperation("key lengths >20 bytes is not supported");
        }
        secret = ByteBuffer.allocate(KEY_LENGTH).put(secret).array();

        int cfgFlags = ConfigurationBuilder.CFGFLAG_IS_CHAL_RESP | ConfigurationBuilder.CFGFLAG_CHAL_HMAC | ConfigurationBuilder.CFGFLAG_HMAC_LT64;
        if (requireTouch) {
            cfgFlags |= ConfigurationBuilder.CFGFLAG_CHAL_BTN_TRIG;
        }

        sendConfiguration(slot, new ConfigurationBuilder()
                .key(ConfigurationBuilder.MODE_HMAC_SHA1, secret)
                .tktFlags((byte) (ConfigurationBuilder.TKTFLAG_UPDATE_MASK | ConfigurationBuilder.TKTFLAG_CHAL_RESP))
                .extFlags(ConfigurationBuilder.EXTFLAG_UPDATE_MASK)
                .cfgFlags((byte) cfgFlags)
                .build());
    }

    /**
     * Configures YubiKey to return static password on touch
     *
     * @param scanCodes the password to store on YubiKey as an array of keyboard scan codes.
     * @param slot      the slot on YubiKey that will be configured with provided password (One - short touch, Two - long touch)
     * @throws IOException           in case of communication error
     * @throws ApduException         in case of unexpected usage or error response from YubiKey
     * @throws BadResponseException  in case of an invalid response from the YubiKey
     * @throws NotSupportedOperation if the command is not supported for this YubiKey
     */
    public void setStaticPassword(byte[] scanCodes, Slot slot) throws IOException, ApduException, NotSupportedOperation, BadResponseException {
        if (version.isLessThan(2, 2, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.2+");
        }
        if (scanCodes.length > 38) {
            throw new IllegalArgumentException("password lengths >38 characters is not supported");
        }

        sendConfiguration(slot, new ConfigurationBuilder()
                .cfgFlags(ConfigurationBuilder.CFGFLAG_SHORT_TICKET)
                .tktFlags(ConfigurationBuilder.TKTFLAG_UPDATE_MASK)
                .extFlags(ConfigurationBuilder.EXTFLAG_UPDATE_MASK)
                .key(ConfigurationBuilder.MODE_STATIC, scanCodes)
                .build());
    }


    /**
     * Configures YubiKey to return YubiOTP (one-time password) on touch
     *
     * @param publicId  public id
     * @param privateId private id
     * @param key       the secret key to store on YubiKey
     * @param slot      the slot on YubiKey that will be configured with OTP (One - short touch, Two - long touch)
     * @throws IOException          in case of communication error
     * @throws ApduException        in case of unexpected usage or error response from YubiKey
     * @throws BadResponseException in case of an invalid response from the YubiKey
     */
    public void setOtpKey(byte[] publicId, byte[] privateId, byte[] key, Slot slot) throws IOException, BadResponseException, ApduException {
        if (key.length != 16) {
            throw new IllegalArgumentException("key must be 16 bytes");
        }
        if (privateId.length != 6) {
            throw new IllegalArgumentException("private ID must be 6 bytes");
        }
        if (publicId.length > 16) {
            throw new IllegalArgumentException("public ID must be <= 16 bytes");
        }

        sendConfiguration(slot, new ConfigurationBuilder()
                .fixed(publicId)
                .uid(privateId)
                .key(ConfigurationBuilder.MODE_AES, key)
                .tktFlags(ConfigurationBuilder.TKTFLAG_UPDATE_MASK)
                .extFlags(ConfigurationBuilder.EXTFLAG_UPDATE_MASK)
                .build());
    }

    /**
     * Configures YubiKey to return HOTP
     *
     * @param secret      the 20 bytes secret for YubiKey to store
     * @param slot        the slot on YubiKey that will be configured with HOTP (slot 1 - short touch, slot 2 - long touch)
     * @param hotp8digits if true will generate 8 digits code (default is 6)
     * @throws IOException           in case of communication error
     * @throws ApduException         in case of unexpected usage or error response from YubiKey
     * @throws BadResponseException  in case of an invalid response from the YubiKey
     * @throws NotSupportedOperation if the command is not supported for this YubiKey
     */
    public void setHotpKey(byte[] secret, Slot slot, boolean hotp8digits) throws IOException, NotSupportedOperation, BadResponseException, ApduException {
        if (version.isLessThan(2, 1, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.1+");
        }
        if (secret.length > KEY_LENGTH) {
            throw new NotSupportedOperation("key lengths >20 bytes is not supported");
        }
        secret = ByteBuffer.allocate(KEY_LENGTH).put(secret).array();

        int cfgFlags = 0;
        if (hotp8digits) {
            cfgFlags |= ConfigurationBuilder.CFGFLAG_OATH_HOTP8;
        }

        sendConfiguration(slot, new ConfigurationBuilder()
                .key(ConfigurationBuilder.MODE_HMAC_SHA1, secret)
                .tktFlags(ConfigurationBuilder.TKTFLAG_OATH_HOTP)
                .cfgFlags((byte) cfgFlags)
                .build());
    }

    /**
     * Method allows to swap data between 1st and 2nd slot of the YubiKey
     *
     * @throws IOException           in case of communication error
     * @throws ApduException         in case of unexpected usage or error response from YubiKey
     * @throws BadResponseException  in case of an invalid response from the YubiKey
     * @throws NotSupportedOperation if the command is not supported for this YubiKey
     */
    public void swapSlots() throws IOException, NotSupportedOperation, BadResponseException, ApduException {
        if (version.isLessThan(2, 3, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.3+");
        }

        sendConfiguration(YubiKeySlot.SWAP, new byte[ConfigurationBuilder.CFG_SIZE]);
    }

    private void sendConfiguration(YubiKeySlot slot, byte[] configuration) throws IOException, ApduException, BadResponseException {
        Status newStatus = Status.parse(backend.sendConfig(slot.value, configuration, 0));
        if (status.getProgrammingSequence() == newStatus.getProgrammingSequence()) {
            // if programming sequence is not updated it means that new configuration wasn't saved
            throw new BadResponseException("Failed to change configuration");
        }
        status = newStatus;
    }

    private void sendConfiguration(Slot slot, byte[] config) throws IOException, BadResponseException, ApduException {
        sendConfiguration(slot.map(YubiKeySlot.CONFIG_1, YubiKeySlot.CONFIG_2), config);
    }

    private static abstract class Backend<T extends Closeable> implements Closeable {
        protected final T delegate;

        private Backend(T delegate) {
            this.delegate = delegate;
        }

        abstract byte[] sendConfig(byte slot, byte[] data, int expectedResponseLength) throws IOException, ApduException;

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}
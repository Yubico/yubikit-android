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

package com.yubico.yubikit.configurator;

import com.yubico.yubikit.HidApplication;
import com.yubico.yubikit.Iso7816Application;
import com.yubico.yubikit.apdu.Apdu;
import com.yubico.yubikit.exceptions.ApduException;
import com.yubico.yubikit.apdu.Version;
import com.yubico.yubikit.exceptions.ApplicationNotFound;
import com.yubico.yubikit.exceptions.BadRequestException;
import com.yubico.yubikit.exceptions.BadResponseException;
import com.yubico.yubikit.transport.usb.NoDataException;
import com.yubico.yubikit.exceptions.NotSupportedOperation;
import com.yubico.yubikit.exceptions.YubiKeyCommunicationException;
import com.yubico.yubikit.transport.YubiKeySession;
import com.yubico.yubikit.transport.usb.UsbSession;
import com.yubico.yubikit.utils.Logger;
import com.yubico.yubikit.utils.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Map;

/**
 * Application that allows to calculate HMAC SHA1 using YubiKey
 */
public class YubiKeyConfigurationApplication implements Closeable {

    private static final byte INS_CONFIG = (byte) 0x01;
    private static final byte[] AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01};

    private static final short APPLICATION_NOT_FOUND_ERROR = 0x6a82;

    private static final int KEY_LENGTH = 20;

    /**
     * Response on select of application
     */
    private Status status;

    /**
     * This applet is implemented on 2 interfaces: CCID and HID
     */
    private HidApplication hidApplication;
    private Iso7816Application ccidApplication;

    /**
     * Create new instance of {@link Iso7816Application}
     * and selects the application for use
     *
     * @param session session with YubiKey
     * @throws IOException in case of connection error
     * @throws ApplicationNotFound if the application is missing or disabled.
     */
    public YubiKeyConfigurationApplication(YubiKeySession session) throws IOException, YubiKeyCommunicationException {
        // for configuration via USB use HID interface rather than CCID
        // bcz on YK5+ this app is disabled (or partially disabled)
        // NEO has a bug when challenge-response with touch returns 0x6985 error code
        if (session instanceof UsbSession) {
            try {
                hidApplication = new HidApplication((UsbSession) session);
                status = Status.parse(hidApplication.getStatus());
            } catch (IOException ignore) {
                // if HID interface is not found we will try to connect using CCID
            }
        }

        if (hidApplication == null) {
            try {
                ccidApplication = new Iso7816Application(AID, session);
                byte[] response = ccidApplication.select();
                Logger.d("Select OTP applet: " + StringUtils.bytesToHex(response));
                status = Status.parse(response);
            } catch (ApduException e) {
                if (e.getStatusCode() == APPLICATION_NOT_FOUND_ERROR) {
                    throw new ApplicationNotFound("Configuration application is disabled on this device");
                } else {
                    throw e;
                }
            } finally {
                if (status == null) {
                    close();
                }
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (ccidApplication != null) {
            ccidApplication.close();
        }
        if (hidApplication != null) {
            hidApplication.close();
        }
    }

    /**
     * Calculates HMAC-SHA1 on given challenge (using secret that configured/programmed on YubiKey)
     *
     * @param challenge generated challenge that will be sent
     * @param slot      the slot on YubiKey that configured with challenge response secret
     * @return response on challenge returned from YubiKey
     * @throws IOException   in case of communication error
     */
    public byte[] calculateHmacSha1(byte[] challenge, Slot slot) throws IOException, ApduException, NotSupportedOperation {
        // works on version above 2.2
        if (getVersion().isLessThan(2, 2, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.2+");
        }

        byte slotValue = slot == Slot.ONE ? YubiKeySlot.CHALLENGE_HMAC_1.value : YubiKeySlot.CHALLENGE_HMAC_2.value;
        if (hidApplication == null) {
            return ccidApplication.sendAndReceive(new Apdu(0, INS_CONFIG, slotValue, 0, challenge));
        } else {
            hidApplication.send(slotValue, challenge);
            int expectedResponseLength = 20;
            // response for HMAC-SHA1 challenge response is always 20 bytes
            // but YubiKey also returns extra data (2 bytes of CRC and 6 bytes of 0x00 at the end)
            try {
                byte[] response = hidApplication.receive(expectedResponseLength);
                return Arrays.copyOf(response, expectedResponseLength);
            } catch (NoDataException e) {
                return new byte[0];
            }
        }
    }

    /**
     * Configures HMAC-SHA1 challenge response secret on YubiKey
     * (@see calculateHmacSha1() how to use it after configuration)
     *
     * @param secret the 20 bytes secret for YubiKey to store
     * @param slot   the slot on YubiKey that will be configured with challenge response secret
     * @throws IOException   in case of communication error
     */
    public void setHmacSha1ChallengeResponseSecret(byte[] secret, Slot slot, boolean requireTouch) throws IOException, NotSupportedOperation, BadResponseException, ApduException {
        if (getVersion().isLessThan(2, 2, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.2+");
        }

        if (secret == null || secret.length > KEY_LENGTH) {
            throw new NotSupportedOperation("key lengths >20 bytes is not supported");
        }
        secret = ByteBuffer.allocate(KEY_LENGTH).put(secret).array();

        ConfigurationBuilder configurationBuilder = new ConfigurationBuilder();
        configurationBuilder.setKey(ConfigurationBuilder.HMAC_SHA1_MODE, secret);
        configurationBuilder.setTktFlags((byte) (ConfigurationBuilder.TKTFLAG_UPDATE_MASK | ConfigurationBuilder.TKTFLAG_CHAL_RESP));
        configurationBuilder.setExtFlags(ConfigurationBuilder.EXTFLAG_UPDATE_MASK);

        int cfgFlags = ConfigurationBuilder.CFGFLAG_IS_CHAL_RESP | ConfigurationBuilder.CFGFLAG_CHAL_HMAC | ConfigurationBuilder.CFGFLAG_HMAC_LT64;
        if (requireTouch) {
            cfgFlags |= ConfigurationBuilder.CFGFLAG_CHAL_BTN_TRIG;
        }
        configurationBuilder.setCfgFlags((byte) cfgFlags);
        sendConfiguration(slot, configurationBuilder);
    }

    /**
     * Configures YubiKey to return static password on touch
     *
     * @param scanCodes the password to store on YubiKey as an array of keyboard scan codes.
     * @param slot the slot on YubiKey that will be configured with provided password (One - short touch, Two - long touch)
     * @throws IOException in case of communication error
     * @throws ApduException in case of unexpected usage or error response from YubiKey
     */
    public void setStaticPassword(byte[] scanCodes, Slot slot) throws IOException, ApduException, BadRequestException, BadResponseException {
        if (getVersion().isLessThan(2, 2, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.2+");
        }
        if (scanCodes == null || scanCodes.length > 38) {
            throw new BadRequestException("password lengths >38 characters is not supported");
        }

        ConfigurationBuilder configurationBuilder = new ConfigurationBuilder();
        configurationBuilder.setCfgFlags(ConfigurationBuilder.CFGFLAG_SHORT_TICKET);
        configurationBuilder.setTktFlags(ConfigurationBuilder.TKTFLAG_UPDATE_MASK);
        configurationBuilder.setExtFlags(ConfigurationBuilder.EXTFLAG_UPDATE_MASK);
        configurationBuilder.setKey(ConfigurationBuilder.STATIC_MODE, scanCodes);
        sendConfiguration(slot, configurationBuilder);
    }


    /**
     * Configures YubiKey to return YubiOTP (one-time password) on touch
     *
     * @param publicId public id
     * @param privateId private id
     * @param key       the secret key to store on YubiKey
     * @param slot      the slot on YubiKey that will be configured with OTP (One - short touch, Two - long touch)
     * @throws IOException   in case of communication error
     */
    public void setOtpKey(byte[] publicId, byte[] privateId, byte[] key, Slot slot) throws IOException, NotSupportedOperation, BadResponseException, ApduException {
        if (key.length != 16) {
            throw new NotSupportedOperation("key must be 16 bytes");
        }
        if (privateId.length != 6) {
            throw new NotSupportedOperation("private ID must be 6 bytes");
        }
        if (publicId.length > 16) {
            throw new NotSupportedOperation("public ID must be <= 16 bytes");
        }

        ConfigurationBuilder configurationBuilder = new ConfigurationBuilder();
        configurationBuilder.setFixed(publicId);
        configurationBuilder.setUid(privateId);
        configurationBuilder.setKey(ConfigurationBuilder.AES_MODE, key);
        configurationBuilder.setTktFlags(ConfigurationBuilder.TKTFLAG_UPDATE_MASK);
        configurationBuilder.setExtFlags(ConfigurationBuilder.EXTFLAG_UPDATE_MASK);
        sendConfiguration(slot, configurationBuilder);
    }

    /**
     * Configures YubiKey to return HOTP
     *
     * @param secret      the 20 bytes secret for YubiKey to store
     * @param slot        the slot on YubiKey that will be configured with HOTP (slot 1 - short touch, slot 2 - long touch)
     * @param hotp8digits if true will generate 8 digits code (default is 6)
     * @throws IOException   in case of communication error
     */
    public void setHotpKey(byte[] secret, Slot slot, boolean hotp8digits) throws IOException, NotSupportedOperation, BadResponseException, ApduException {
        if (getVersion().isLessThan(2, 1, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.1+");
        }
        if (secret == null || secret.length > KEY_LENGTH) {
            throw new NotSupportedOperation("key lengths >20 bytes is not supported");
        }
        secret = ByteBuffer.allocate(KEY_LENGTH).put(secret).array();

        ConfigurationBuilder configurationBuilder = new ConfigurationBuilder();
        configurationBuilder.setKey(ConfigurationBuilder.HMAC_SHA1_MODE, secret);
        configurationBuilder.setTktFlags(ConfigurationBuilder.TKTFLAG_OATH_HOTP);

        int cfgFlags = 0;
        if (hotp8digits) {
            cfgFlags |= ConfigurationBuilder.CFGFLAG_OATH_HOTP8;
        }
        configurationBuilder.setCfgFlags((byte) cfgFlags);
        sendConfiguration(slot, configurationBuilder);
    }

    /**
     * Method allows to swap data between 1st and 2nd slot of the YubiKey
     *
     * @throws IOException   in case of communication error
     */
    public void swapSlots() throws IOException, NotSupportedOperation, BadResponseException, ApduException {
        if (getVersion().isLessThan(2, 3, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 2.3+");
        }

        sendConfiguration(YubiKeySlot.SWAP.value, new byte[ConfigurationBuilder.CFG_SIZE]);
    }

    /**
     * Firmware version
     *
     * @return Yubikey firmware version
     */
    public Version getVersion() {
        return status.getVersion();
    }

    /**
     * Helper method to send configuration blob over HID or CCID (depending on what interface was open)
     *
     * @param slotValue     command that needs to be send to YubiKey (@see YubiKeySlot)
     * @param configuration data that associated with command
     * @throws IOException   in case of communication error
     */
    private void sendConfiguration(byte slotValue, byte[] configuration) throws IOException, ApduException, BadResponseException {
        Status newStatus;
        if (hidApplication == null) {
            byte[] response = ccidApplication.sendAndReceive(new Apdu(0, INS_CONFIG, slotValue, 0, configuration));
            newStatus = Status.parse(response);
        } else {
            hidApplication.send(slotValue, configuration);
            try {
                hidApplication.receive(0);
            } catch (NoDataException ignore) {
                //we don't expect any data to be returned but wait status to be updated
            }
            newStatus = Status.parse(hidApplication.getStatus());
        }
        if (status.getProgrammingSequence() == newStatus.getProgrammingSequence()) {
            // if programming sequence is not updated it means that new configuration wasn't saved
            throw new BadResponseException("Failed to change configuration");
        }
        status = newStatus;
    }

    /**
     * Helper method to send configuration blob over HID or CCID (depending on what interface was open)
     * Sends command to update configuration on key (what type of secret to store and the secret itself including different flags)
     *
     * @param slot                 the slot on YubiKey for OTP applet (@see Slot)
     * @param configurationBuilder data builder that contains data associated with command
     * @throws IOException   in case of communication error
     */
    private void sendConfiguration(Slot slot, ConfigurationBuilder configurationBuilder) throws IOException, BadResponseException, ApduException {
        byte slotValue = slot == Slot.ONE ? YubiKeySlot.CONFIG_1.value : YubiKeySlot.CONFIG_2.value;
        sendConfiguration(slotValue, configurationBuilder.build());
    }
}

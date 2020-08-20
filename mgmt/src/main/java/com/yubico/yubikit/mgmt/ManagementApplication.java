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

package com.yubico.yubikit.mgmt;

import com.yubico.yubikit.ctaphid.FidoApplication;
import com.yubico.yubikit.ctaphid.FidoConnection;
import com.yubico.yubikit.exceptions.ApplicationNotAvailableException;
import com.yubico.yubikit.exceptions.CommandException;
import com.yubico.yubikit.exceptions.NotSupportedOperation;
import com.yubico.yubikit.iso7816.Apdu;
import com.yubico.yubikit.iso7816.ApduException;
import com.yubico.yubikit.iso7816.Iso7816Application;
import com.yubico.yubikit.iso7816.Iso7816Connection;
import com.yubico.yubikit.keyboard.ChecksumUtils;
import com.yubico.yubikit.keyboard.OtpApplication;
import com.yubico.yubikit.keyboard.OtpConnection;
import com.yubico.yubikit.utils.Interface;
import com.yubico.yubikit.utils.Logger;
import com.yubico.yubikit.utils.StringUtils;
import com.yubico.yubikit.utils.Version;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;

import javax.annotation.Nullable;

/**
 * Implements management API to YubiKey interface
 * https://developers.yubico.com/yubikey-manager/Config_Reference.html
 */
public class ManagementApplication implements Closeable {
    private static final byte[] AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17};

    /**
     * Instruction set for MGMT application
     */
    private static final byte INS_READ_CONFIG = 0x1d;
    private static final byte INS_WRITE_CONFIG = 0x1c;
    private static final byte INS_SET_MODE = 0x16;


    private static final byte SLOT_DEVICE_CONFIG = 0x11;
    private static final byte SLOT_YK4_CAPABILITIES = 0x13;
    private static final byte SLOT_YK4_SET_DEVICE_INFO = 0x15;

    private static final byte P1_DEVICE_CONFIG = 0x11;

    private static final byte CTAP_TYPE_INIT = (byte) 0x80;
    private static final byte CTAP_VENDOR_FIRST = 0x40;
    private static final byte CTAP_YUBIKEY_DEVICE_CONFIG = CTAP_TYPE_INIT | CTAP_VENDOR_FIRST;
    private static final byte CTAP_READ_CONFIG = CTAP_TYPE_INIT | CTAP_VENDOR_FIRST + 2;
    private static final byte CTAP_WRITE_CONFIG = CTAP_TYPE_INIT | CTAP_VENDOR_FIRST + 3;

    /**
     * This applet is implemented on 2 interfaces: CCID and HID
     */
    private final Backend<?> backend;

    /**
     * Firmware version
     */
    private final Version version;

    /**
     * Create new instance of {@link ManagementApplication} over an {@link Iso7816Connection}.
     *
     * @param connection connection with YubiKey
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public ManagementApplication(Iso7816Connection connection) throws IOException, ApplicationNotAvailableException {
        Iso7816Application app = new Iso7816Application(AID, connection);
        version = Version.parse(new String(app.select()));
        backend = new Backend<Iso7816Application>(app) {
            @Override
            byte[] readConfig() throws IOException, CommandException {
                return delegate.sendAndReceive(new Apdu(0, INS_READ_CONFIG, 0, 0, null));
            }

            @Override
            void writeConfig(byte[] config) throws IOException, CommandException {
                delegate.sendAndReceive(new Apdu(0, INS_WRITE_CONFIG, 0, 0, config));
            }

            @Override
            void setMode(byte[] data) throws IOException, CommandException {
                delegate.sendAndReceive(new Apdu(0, INS_SET_MODE, P1_DEVICE_CONFIG, 0, data));
            }
        };
    }

    /**
     * Create new instance of {@link ManagementApplication} over an {@link OtpConnection}.
     *
     * @param connection connection with YubiKey
     * @throws IOException in case of connection error
     */
    public ManagementApplication(OtpConnection connection) throws IOException, ApplicationNotAvailableException {
        OtpApplication application = new OtpApplication(connection);
        version = Version.parse(application.readStatus());
        if (version.isLessThan(3, 0, 0)) {
            throw new ApplicationNotAvailableException("Management Application requires YubiKey 3 or later");
        }
        backend = new Backend<OtpApplication>(application) {
            @Override
            byte[] readConfig() throws IOException {
                byte[] response = delegate.transceive(SLOT_YK4_CAPABILITIES, null, null);
                Logger.d("Check CRC: " + StringUtils.bytesToHex(response) + " length: " + (response[0] + 1));
                if (ChecksumUtils.checkCrc(response, response[0] + 1 + 2)) {
                    return Arrays.copyOf(response, response[0] + 1);
                }
                throw new IOException("Invalid CRC");
            }

            @Override
            void writeConfig(byte[] config) throws IOException {
                delegate.transceive(SLOT_YK4_SET_DEVICE_INFO, config, null);
            }

            @Override
            void setMode(byte[] data) throws IOException {
                delegate.transceive(SLOT_DEVICE_CONFIG, data, null);
            }
        };
    }

    /**
     * Create new instance of a ManagementApplication over a FidoConnection.
     *
     * @param connection a connection over the FIDO USB transport with a YubiKey
     * @throws IOException in case of connection error
     */
    public ManagementApplication(FidoConnection connection) throws IOException {
        FidoApplication app = new FidoApplication(connection);
        version = app.getVersion();
        backend = new Backend<FidoApplication>(app) {
            @Override
            byte[] readConfig() throws IOException {
                Logger.d("Reading fido config...");
                return delegate.sendAndReceive(CTAP_READ_CONFIG, new byte[0], null);
            }

            @Override
            void writeConfig(byte[] config) throws IOException {
                delegate.sendAndReceive(CTAP_WRITE_CONFIG, config, null);
            }

            @Override
            void setMode(byte[] data) throws IOException {
                delegate.sendAndReceive(CTAP_YUBIKEY_DEVICE_CONFIG, data, null);
            }
        };
    }

    @Override
    public void close() throws IOException {
        backend.close();
    }

    /**
     * Firmware version
     *
     * @return Yubikey firmware version
     */
    public Version getVersion() {
        return version;
    }

    public DeviceInfo readDeviceInfo() throws IOException, CommandException {
        if (version.isLessThan(4, 1, 0)) {
            //TODO: Provide fallback?
            throw new NotSupportedOperation("Operation is not supported on versions below 4");
        }

        return DeviceInfo.parse(backend.readConfig(), version);
    }

    /**
     * Write device configuration to a YubiKey 5 or later.
     *
     * @param config          the device configuration to write
     * @param reboot          if true cause the YubiKey to immediately reboot, applying the new configuration
     * @param currentLockCode required if a configuration lock code is set
     * @param newLockCode     changes or removes (if 16 byte all-zero) the configuration lock code
     * @throws IOException      in case of connection error
     * @throws CommandException in case of error response
     */
    public void writeDeviceConfig(DeviceConfig config, boolean reboot, @Nullable byte[] currentLockCode, @Nullable byte[] newLockCode) throws IOException, CommandException {
        if (version.isLessThan(5, 0, 0)) {
            throw new NotSupportedOperation("Requires YubiKey 5.0.0 or later");
        }
        byte[] data = config.getBytes(reboot, currentLockCode, newLockCode);
        backend.writeConfig(data);
    }

    /**
     * Write device configuration for YubiKey NEO and YubiKey 4.
     *
     * @param mode             USB transport mode to set
     * @param chalrespTimeout  timeout (seconds) for challenge-response requiring touch.
     * @param autoejectTimeout timeout (10x seconds) for auto-eject (only used for CCID-only mode).
     * @throws IOException           in case of connection error
     * @throws ApduException         in case of communication or not supported operation error
     * @throws NotSupportedOperation if this command is not supported for this YubiKey
     */
    public void setMode(UsbTransport.Mode mode, byte chalrespTimeout, short autoejectTimeout) throws IOException, CommandException {
        if (version.isLessThan(3, 0, 0)) {
            throw new NotSupportedOperation("Requires YubiKey 3.0.0 or later");
        }
        if (version.isAtLeast(5, 0, 0)) {
            //Translate into DeviceConfig and set using writeDeviceConfig
            int usbEnabled = 0;
            if ((mode.transports & UsbTransport.OTP) != 0) {
                usbEnabled |= Application.OTP;
            }
            if ((mode.transports & UsbTransport.CCID) != 0) {
                usbEnabled |= Application.OATH | Application.PIV | Application.OPGP;
            }
            if ((mode.transports & UsbTransport.FIDO) != 0) {
                usbEnabled |= Application.U2F | Application.FIDO2;
            }
            writeDeviceConfig(
                    new DeviceConfig.Builder()
                            .enabledApplications(Interface.USB, usbEnabled)
                            .challengeResponseTimeout(chalrespTimeout)
                            .autoEjectTimeout(autoejectTimeout)
                            .build(),
                    false, null, null);
        } else {
            byte[] data = ByteBuffer.allocate(4).put(mode.value).put(chalrespTimeout).putShort(autoejectTimeout).array();
            backend.setMode(data);
        }
    }

    private static abstract class Backend<T extends Closeable> implements Closeable {
        protected final T delegate;

        private Backend(T delegate) {
            this.delegate = delegate;
        }

        abstract byte[] readConfig() throws IOException, CommandException;

        abstract void writeConfig(byte[] config) throws IOException, CommandException;

        abstract void setMode(byte[] data) throws IOException, CommandException;

        @Override
        public void close() throws IOException {
            delegate.close();
        }
    }
}

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

package com.yubico.yubikit.management;

import com.yubico.yubikit.HidApplication;
import com.yubico.yubikit.Iso7816Application;
import com.yubico.yubikit.apdu.Apdu;
import com.yubico.yubikit.apdu.ApduCodeException;
import com.yubico.yubikit.apdu.ApduException;
import com.yubico.yubikit.apdu.Tlv;
import com.yubico.yubikit.apdu.TlvUtils;
import com.yubico.yubikit.apdu.Version;
import com.yubico.yubikit.configurator.Status;
import com.yubico.yubikit.exceptions.ApplicationNotFound;
import com.yubico.yubikit.exceptions.NoDataException;
import com.yubico.yubikit.exceptions.NotSupportedOperation;
import com.yubico.yubikit.transport.YubiKeySession;
import com.yubico.yubikit.transport.usb.UsbSession;
import com.yubico.yubikit.utils.ChecksumUtils;
import com.yubico.yubikit.utils.Logger;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * Implements management API to YubiKey interface
 * https://developers.yubico.com/yubikey-manager/Config_Reference.html
 */
public class ManagementApplication implements Closeable {

    private static final byte[] AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x47, 0x11, 0x17};
    private static final byte[] YUBIKEY_AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x20, 0x01, 0x01};

    /**
     * Instruction set for MGMT application
     */
    private static final byte INS_SELECT = (byte) 0xa4;
    private static final byte INS_READ_CONFIG = 0x1d;
    private static final byte INS_WRITE_CONFIG = 0x1c;
    private static final byte INS_SET_MODE = 0x16;

    private static final byte P1_DEVICE_CONFIG = 0x11;

    private static final byte TAG_REBOOT = 0x0c;

    private static final short APPLICATION_NOT_FOUND_ERROR = 0x6a82;

    /**
     * This applet is implemented on 2 interfaces: CCID and HID
     */
    private Iso7816Application ccidApplication;
    private HidApplication hidApplication;

    /**
     * Firmware version
     */
    private Version version;

    /**
     * Create new instance of {@link ManagementApplication}
     *
     * @param session session with YubiKey
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public ManagementApplication(YubiKeySession session) throws IOException, ApduException {
        try {
            ccidApplication = new Iso7816Application(session);
            byte[] response = ccidApplication.sendAndReceive(new Apdu(0, INS_SELECT, 0x04, 0, AID));
            version = Version.parse(new String(response));
        } catch (IOException | ApduCodeException e) {
            // Unable to connect to CCID applet, attempt to fallback to HID.
            if (session instanceof UsbSession) {
                try {
                    hidApplication = new HidApplication((UsbSession) session);
                    Status status = Status.parse(hidApplication.getStatus());
                    version = status.getVersion();
                } catch (IOException ignore) {
                    // if HID interface is not found we will fallthrough to close
                }
            }
        }
        if (version == null) {
            close();
            throw new ApplicationNotFound("Management application couldn't be accessed");
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
     * Firmware version
     *
     * @return Yubikey firmware version
     */
    public Version getVersion() {
        return version;
    }

    /**
     * Reads configurations from device
     *
     * @return configurations
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication or not supported operation error
     */
    public DeviceConfiguration readConfiguration() throws IOException, ApduException {
        if (version.major < 4) {
            throw new NotSupportedOperation("Operation is not supported on versions below 4");
        }
        if (ccidApplication != null) {
            byte[] response = ccidApplication.sendAndReceive(new Apdu(0, INS_READ_CONFIG, 0, 0, null));
            if (response.length == 0 || (response[0] & 0xff) != response.length - 1) {
                throw new IOException("Invalid response");
            }

            return new DeviceConfiguration(response, version);
        } else {
            hidApplication.send((byte) 0x13, new byte[0]); // SLOT_YK4_CAPABILITIES
            byte[] response = hidApplication.receive(0);
            if (response.length == 0 || !ChecksumUtils.checkCrc(response, response.length)) {
                throw new IOException("Invalid response");
            }

            return new DeviceConfiguration(response, version);
        }
    }

    /**
     * Writes updates
     *
     * @param config updated configurations
     * @param reboot require reboot
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication or not supported operation error
     */
    public void writeConfiguration(DeviceConfiguration config, boolean reboot) throws IOException, ApduException {
        if (config.getFirmwareVersion().major < 4) {
            throw new NotSupportedOperation("Operation is not supported on versions below 5");
        }
        if (config.isConfigLocked()) {
            throw new NotSupportedOperation("Configuration is locked");
        }
        List<Tlv> output = config.getChangedData();
        if (reboot) {
            output.add(new Tlv(TAG_REBOOT, new byte[0]));
        }
        byte[] configBytes = TlvUtils.packTlvList(output);
        byte[] data = ByteBuffer.allocate(1 + configBytes.length).put((byte) configBytes.length).put(configBytes).array();

        if (ccidApplication != null) {
            byte[] response = ccidApplication.sendAndReceive(new Apdu(0, INS_WRITE_CONFIG, 0, 0, data));
        } else {
            hidApplication.send((byte) 0x15, data); //SLOT_YK4_SET_DEVICE_INFO
            try {
                hidApplication.receive(0);
            } catch (NoDataException ignore) {
                //we don't expect any data to be returned but wait status to be updated
            }
        }
        config.dataChanged();
    }

    /**
     * Enables/disables USB capability on the key
     *
     * @param config updated configurations
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication or not supported operation error
     */
    public void setMode(DeviceConfiguration config) throws IOException, ApduException {
        if (version.major > 4) {
            throw new NotSupportedOperation("Use writeConfiguration() for versions 5 and above");
        }
        if (config.isConfigLocked()) {
            throw new NotSupportedOperation("Configuration is locked");
        }

        // this method doesn't turn off CCID to keep ability to change settings with this application
        ccidApplication.sendAndReceive(new Apdu(0, INS_SET_MODE, P1_DEVICE_CONFIG, 0, new byte[]{getModeType(config).value}));
    }

    private static ModeType getModeType(DeviceConfiguration config) {
        if (!isUsbApplicationEnabled(config, ApplicationType.OTP)) {
            if (!isUsbApplicationEnabled(config, ApplicationType.U2F)) {
                return ModeType.CCID;
            } else {
                return ModeType.FIDO_CCID;
            }
        } else if (!isUsbApplicationEnabled(config, ApplicationType.U2F)) {
            return ModeType.OTP_CCID;
        } else {
            return ModeType.OTP_FIDO_CCID;
        }
    }

    private static boolean isUsbApplicationEnabled(DeviceConfiguration config, ApplicationType appType) {
        return config.getEnabled(TransportType.USB, appType);
    }
}

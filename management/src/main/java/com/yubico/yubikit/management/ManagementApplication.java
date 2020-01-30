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

import com.yubico.yubikit.Iso7816Application;
import com.yubico.yubikit.apdu.Apdu;
import com.yubico.yubikit.apdu.ApduCodeException;
import com.yubico.yubikit.apdu.ApduException;
import com.yubico.yubikit.apdu.Tlv;
import com.yubico.yubikit.apdu.TlvUtils;
import com.yubico.yubikit.apdu.Version;
import com.yubico.yubikit.exceptions.ApplicationNotFound;
import com.yubico.yubikit.exceptions.NotSupportedOperation;
import com.yubico.yubikit.transport.YubiKeySession;
import com.yubico.yubikit.utils.Logger;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.List;

/**
 * Implements management API to YubiKey interface
 * https://developers.yubico.com/yubikey-manager/Config_Reference.html
 */
public class ManagementApplication extends Iso7816Application {

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
     * Firmware version
     */
    private Version version;

    /**
     * Create new instance of {@link ManagementApplication}
     * @param session session with YubiKey
     * @throws IOException in case of connection error
     * @throws ApduException in case of communication error
     */
    public ManagementApplication(YubiKeySession session)  throws IOException, ApduException {
        super(session);
        try {
            byte[] response = sendAndReceive(new Apdu(0, INS_SELECT, 0x04, 0, AID));
            // last part of message is firmware version
            version = Version.parse(new String(response));
        } catch (ApduCodeException e) {
            if (e.getStatusCode() == APPLICATION_NOT_FOUND_ERROR) {
                // application is not found, most probably we have old firmware but let's make sure with OTP application
                try {
                    Logger.d("select OTP application to determine if management application is supported");
                    byte[] response = sendAndReceive(new Apdu(0, INS_SELECT, 0x04, 0, YUBIKEY_AID));
                    Version otpVersion = Version.parse(response);

                    // workaround for firmware versions that were not detected correctly
                    if (otpVersion.major < 1) {
                        otpVersion = new Version(5,version.minor,version.micro);
                    }

                    if ((int)otpVersion.major < 4) {
                        throw new NotSupportedOperation("Management application API supported only from version 4 and above");
                    }
                } catch (ApduCodeException ignore) {
                    // do nothing if this application is not found, we use it only to detect firmware version on old devices
                    Logger.d("OTP application is not enabled on this device");
                }

                throw new ApplicationNotFound("Management application is disabled on this device");
            } else {
                throw e;
            }
        }
    }

    /**
     * Firmware version
     * @return Yubikey firmware version
     */
    public Version getVersion() {
        return version;
    }

    /**
     * Reads configurations from device
     * @return configurations
     * @throws IOException in case of connection error
     * @throws ApduException in case of communication or not supported operation error
     */
    public DeviceConfiguration readConfiguration() throws IOException, ApduException {
        if (version.major < 4) {
            throw new NotSupportedOperation("Operation is not supported on versions below 4");
        }
        byte[] response = sendAndReceive(new Apdu(0, INS_READ_CONFIG, 0, 0, null));
        if (response.length == 0 || (response[0] & 0xff) != response.length - 1) {
            throw new IOException("Invalid response");
        }

        return new DeviceConfiguration(response, version);
    }

    /**
     * Writes updates
     * @param config updated configurations
     * @param reboot require reboot
     * @throws IOException in case of connection error
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
        byte[] configBytes = TlvUtils.TlvToData(output);
        byte[] data = ByteBuffer.allocate(1 + configBytes.length).put((byte) configBytes.length).put(configBytes).array();
        sendAndReceive(new Apdu(0, INS_WRITE_CONFIG, 0, 0, data));
        config.dataChanged();
    }

    /**
     * Enables/disables USB capability on the key
     * @param config updated configurations
     * @throws IOException in case of connection error
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
        sendAndReceive(new Apdu(0, INS_SET_MODE, P1_DEVICE_CONFIG, 0, new byte[] { getModeType(config).value }));
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

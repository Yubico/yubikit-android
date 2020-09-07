package com.yubico.yubikit.mgmt;

import com.yubico.yubikit.utils.Interface;
import com.yubico.yubikit.utils.TlvUtils;
import com.yubico.yubikit.utils.Version;
import com.yubico.yubikit.exceptions.BadResponseException;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Nullable;

public class DeviceInfo {
    private static final int TAG_USB_SUPPORTED = 0x01;
    private static final int TAG_SERIAL_NUMBER = 0x02;
    private static final int TAG_USB_ENABLED = 0x03;
    private static final int TAG_FORMFACTOR = 0x04;
    private static final int TAG_FIRMWARE_VERSION = 0x05;
    private static final int TAG_AUTO_EJECT_TIMEOUT = 0x06;
    private static final int TAG_CHALLENGE_RESPONSE_TIMEOUT = 0x07;
    private static final int TAG_DEVICE_FLAGS = 0x08;
    private static final int TAG_NFC_SUPPORTED = 0x0d;
    private static final int TAG_NFC_ENABLED = 0x0e;
    private static final int TAG_CONFIG_LOCKED = 0x0a;

    private final DeviceConfig config;
    @Nullable
    private final Integer serial;
    private final Version version;
    private final FormFactor formFactor;
    private final Map<Interface, Integer> supportedApplications;
    private final boolean isLocked;

    private DeviceInfo(DeviceConfig config, @Nullable Integer serial, Version version, FormFactor formFactor, Map<Interface, Integer> supportedApplications, boolean isLocked) {
        this.config = config;
        this.serial = serial;
        this.version = version;
        this.formFactor = formFactor;
        this.supportedApplications = supportedApplications;
        this.isLocked = isLocked;
    }

    public DeviceConfig getConfig() {
        return config;
    }

    @Nullable
    public Integer getSerial() {
        return serial;
    }

    public Version getVersion() {
        return version;
    }

    public FormFactor getFormFactor() {
        return formFactor;
    }

    public int getSupportedApplications(Interface iface) {
        Integer applications = supportedApplications.get(iface);
        return applications == null ? 0 : applications;
    }

    public boolean isLocked() {
        return isLocked;
    }

    static DeviceInfo parse(byte[] response, Version defaultVersion) throws BadResponseException {
        int length = response[0] & 0xff;
        if (length != response.length - 1) {
            throw new BadResponseException("Invalid length");
        }

        Map<Integer, byte[]> data = TlvUtils.parseTlvMap(Arrays.copyOfRange(response, 1, length));

        boolean isLocked = readInt(data.get(TAG_CONFIG_LOCKED)) == 1;
        int serial = readInt(data.get(TAG_SERIAL_NUMBER));
        FormFactor formFactor = FormFactor.valueOf(readInt(data.get(TAG_FORMFACTOR)));

        Version version;
        if (data.containsKey(TAG_FIRMWARE_VERSION)) {
            version = Version.parse(data.get(TAG_FIRMWARE_VERSION));
        } else {
            version = defaultVersion;
        }

        short autoEjectTimeout = (short) readInt(data.get(TAG_AUTO_EJECT_TIMEOUT));
        byte challengeResponseTimeout = (byte) readInt(data.get(TAG_CHALLENGE_RESPONSE_TIMEOUT));
        int deviceFlags = readInt(data.get(TAG_DEVICE_FLAGS));

        Map<Interface, Integer> supportedApplications = new HashMap<>();
        supportedApplications.put(Interface.USB, readInt(data.get(TAG_USB_SUPPORTED)));
        supportedApplications.put(Interface.NFC, readInt(data.get(TAG_NFC_SUPPORTED)));

        Map<Interface, Integer> enabledApplications = new HashMap<>();
        enabledApplications.put(Interface.USB, readInt(data.get(TAG_USB_ENABLED)));
        enabledApplications.put(Interface.NFC, readInt(data.get(TAG_NFC_ENABLED)));

        return new DeviceInfo(
                new DeviceConfig(
                        enabledApplications,
                        autoEjectTimeout,
                        challengeResponseTimeout,
                        deviceFlags
                ), serial, version, formFactor, supportedApplications, isLocked
        );
    }

    /**
     * Reads an int from a variable length byte array.
     */
    private static int readInt(@Nullable byte[] data) {
        if (data == null || data.length == 0) {
            return 0;
        }
        int value = 0;
        for (byte b : data) {
            value <<= 8;
            value += (0xff & b);
        }
        return value;
    }
}

package com.yubico.yubikit.mgmt;

import com.yubico.yubikit.utils.Interface;
import com.yubico.yubikit.utils.TlvUtils;

import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.annotation.Nullable;

public class DeviceConfig {
    private static final int TAG_USB_ENABLED = 0x03;
    private static final int TAG_AUTO_EJECT_TIMEOUT = 0x06;
    private static final int TAG_CHALLENGE_RESPONSE_TIMEOUT = 0x07;
    private static final int TAG_DEVICE_FLAGS = 0x08;
    private static final int TAG_NFC_ENABLED = 0x0e;
    private static final int TAG_CONFIGURATION_LOCK = 0x0a;
    private static final int TAG_UNLOCK = 0x0b;
    private static final int TAG_REBOOT = 0x0c;

    private final Map<Interface, Integer> enabledApplications;
    @Nullable
    private final Short autoEjectTimeout;
    @Nullable
    private final Byte challengeResponseTimeout;
    @Nullable
    private final Integer deviceFlags;

    DeviceConfig(Map<Interface, Integer> enabledApplications, @Nullable Short autoEjectTimeout, @Nullable Byte challengeResponseTimeout, @Nullable Integer deviceFlags) {
        this.enabledApplications = enabledApplications;
        this.autoEjectTimeout = autoEjectTimeout;
        this.challengeResponseTimeout = challengeResponseTimeout;
        this.deviceFlags = deviceFlags;
    }

    public Integer getEnabledApplications(Interface iface) {
        return enabledApplications.get(iface);
    }

    @Nullable
    public Short getAutoEjectTimeout() {
        return autoEjectTimeout;
    }

    @Nullable
    public Byte getChallengeResponseTimeout() {
        return challengeResponseTimeout;
    }

    @Nullable
    public Integer getDeviceFlags() {
        return deviceFlags;
    }

    byte[] getBytes(boolean reboot, @Nullable byte[] currentLockCode, @Nullable byte[] newLockCode) {
        Map<Integer, byte[]> values = new LinkedHashMap<>();
        if (reboot) {
            values.put(TAG_REBOOT, null);
        }
        if (currentLockCode != null) {
            values.put(TAG_UNLOCK, currentLockCode);
        }
        Integer usbEnabled = enabledApplications.get(Interface.USB);
        if (usbEnabled != null) {
            values.put(TAG_USB_ENABLED, new byte[]{(byte) (usbEnabled >> 8), usbEnabled.byteValue()});
        }
        Integer nfcEnabled = enabledApplications.get(Interface.NFC);
        if (nfcEnabled != null) {
            values.put(TAG_NFC_ENABLED, new byte[]{(byte) (nfcEnabled >> 8), nfcEnabled.byteValue()});
        }
        if (autoEjectTimeout != null) {
            values.put(TAG_AUTO_EJECT_TIMEOUT, new byte[]{(byte) (autoEjectTimeout >> 8), autoEjectTimeout.byteValue()});
        }
        if (challengeResponseTimeout != null) {
            values.put(TAG_CHALLENGE_RESPONSE_TIMEOUT, new byte[]{challengeResponseTimeout});
        }
        if (deviceFlags != null) {
            values.put(TAG_DEVICE_FLAGS, new byte[]{deviceFlags.byteValue()});
        }
        if (newLockCode != null) {
            values.put(TAG_CONFIGURATION_LOCK, newLockCode);
        }
        byte[] data = TlvUtils.packTlvMap(values);

        if (data.length > 0xff) {
            throw new IllegalStateException("DeviceConfiguration too large");
        }
        return ByteBuffer.allocate(data.length + 1).put((byte) data.length).put(data).array();
    }

    public static class Builder {
        private final Map<Interface, Integer> enabledApplications = new HashMap<>();
        @Nullable
        private Short autoEjectTimeout;
        @Nullable
        private Byte challengeResponseTimeout;
        @Nullable
        private Integer deviceFlags;

        public Builder() {
        }

        public Builder enabledApplications(Interface iface, int applications) {
            enabledApplications.put(iface, applications);
            return this;
        }

        public Builder autoEjectTimeout(short autoEjectTimeout) {
            this.autoEjectTimeout = autoEjectTimeout;
            return this;
        }

        public Builder challengeResponseTimeout(byte challengeResponseTimeout) {
            this.challengeResponseTimeout = challengeResponseTimeout;
            return this;
        }

        public Builder deviceFlags(int deviceFlags) {
            this.deviceFlags = deviceFlags;
            return this;
        }

        public DeviceConfig build() {
            return new DeviceConfig(enabledApplications, autoEjectTimeout, challengeResponseTimeout, deviceFlags);
        }
    }
}

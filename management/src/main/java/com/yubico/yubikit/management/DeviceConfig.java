/*
 * Copyright (C) 2020 Yubico.
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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.util.Tlvs;

import javax.annotation.Nullable;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

public class DeviceConfig {
    private static final int TAG_USB_ENABLED = 0x03;
    private static final int TAG_AUTO_EJECT_TIMEOUT = 0x06;
    private static final int TAG_CHALLENGE_RESPONSE_TIMEOUT = 0x07;
    private static final int TAG_DEVICE_FLAGS = 0x08;
    private static final int TAG_NFC_ENABLED = 0x0e;
    private static final int TAG_CONFIGURATION_LOCK = 0x0a;
    private static final int TAG_UNLOCK = 0x0b;
    private static final int TAG_REBOOT = 0x0c;

    private final Map<Transport, Integer> enabledApplications;
    @Nullable
    private final Short autoEjectTimeout;
    @Nullable
    private final Byte challengeResponseTimeout;
    @Nullable
    private final Integer deviceFlags;

    DeviceConfig(Map<Transport, Integer> enabledApplications, @Nullable Short autoEjectTimeout, @Nullable Byte challengeResponseTimeout, @Nullable Integer deviceFlags) {
        this.enabledApplications = enabledApplications;
        this.autoEjectTimeout = autoEjectTimeout;
        this.challengeResponseTimeout = challengeResponseTimeout;
        this.deviceFlags = deviceFlags;
    }

    /**
     * Get the currently enabled applications for a given Interface.
     * NOTE: This method will return null if the Interface is not supported by the YubiKey, OR if the enabled
     * applications state isn't readable. The YubiKey 4 series, for example, does not return enabled-status for USB
     * applications.
     *
     * @param transport the physical transport to get enabled applications for
     * @return the enabled applications, represented as {@link Capability} bits being set (1) or not (0)
     */
    @Nullable
    public Integer getEnabledApplications(Transport transport) {
        return enabledApplications.get(transport);
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
        Integer usbEnabled = enabledApplications.get(Transport.USB);
        if (usbEnabled != null) {
            values.put(TAG_USB_ENABLED, new byte[]{(byte) (usbEnabled >> 8), usbEnabled.byteValue()});
        }
        Integer nfcEnabled = enabledApplications.get(Transport.NFC);
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
        byte[] data = Tlvs.encodeMap(values);

        if (data.length > 0xff) {
            throw new IllegalStateException("DeviceConfiguration too large");
        }
        return ByteBuffer.allocate(data.length + 1).put((byte) data.length).put(data).array();
    }

    public static class Builder {
        private final Map<Transport, Integer> enabledApplications = new HashMap<>();
        @Nullable
        private Short autoEjectTimeout;
        @Nullable
        private Byte challengeResponseTimeout;
        @Nullable
        private Integer deviceFlags;

        public Builder() {
        }

        public Builder enabledApplications(Transport transport, int applications) {
            enabledApplications.put(transport, applications);
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

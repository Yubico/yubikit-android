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

package com.yubico.yubikit.apdu;

import android.text.TextUtils;

import java.util.Locale;

/**
 * Class that allows to parse version of yubikey
 */
public final class Version {
    public static final Version UNKNOWN = new Version((byte)0,(byte)0,(byte)0);

    public final byte major;
    public final byte minor;
    public final byte micro;

    public Version(int major, int minor, int micro) {
        this((byte) major, (byte) minor, (byte) micro);
    }

    public Version(byte major, byte minor, byte micro) {
        this.major = major;
        this.minor = minor;
        this.micro = micro;
    }

    public byte[] getBytes() {
        return new byte[] {major, minor, micro};
    }

    public int compare(Version version) {
        for (int i = 0; i < 3; i++) {
            byte v1 = this.getBytes()[i];
            byte v2 = version.getBytes()[i];
            if (v1 < v2) {
                return -1;
            }
            if (v1 > v2) {
                return 1;
            }
        }
        return 0;
    }

    public static Version parse(byte[] bytes) {
        if (bytes.length < 3) {
            return UNKNOWN;
        }

        return new Version(bytes[0], bytes[1], bytes[2]);
    }

    /**
     * Parses from string format "Firmware version 5.2.1"
     * @param nameAndVersion string that contains version at the end
     * @return the firmware version
     */
    public static Version parse(String nameAndVersion) {
        if (TextUtils.isEmpty(nameAndVersion)) {
            return UNKNOWN;
        }

        // take only last part of the message
        String[] nameParts = nameAndVersion.split(" ");
        String version = nameParts[nameParts.length - 1];


        String[] parts = version.split("\\.");
        if (parts.length < 3) {
            return UNKNOWN;
        }

        byte[] versionBytes = new byte[3];
        for (int i = 0; i < 3; i++) {
            try {
                versionBytes[i] = (byte)Integer.parseInt(parts[i]);
            } catch (NumberFormatException ignore) {
            }
        }
        return new Version(versionBytes[0], versionBytes[1], versionBytes[2]);
    }

    @Override
    public String toString() {
        return String.format(Locale.ROOT, "%d.%d.%d", 0xff & major, 0xff & minor, 0xff & micro);
    }
}

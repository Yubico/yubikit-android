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

package com.yubico.yubikit.core;


import java.util.Locale;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * A 3-part version number, used by the YubiKey firmware and its various applications.
 *
 *
 */
public final class Version implements Comparable<Version> {
    private static final Pattern VERSION_STRING_PATTERN = Pattern.compile("\\b(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\b");

    public final byte major;
    public final byte minor;
    public final byte micro;

    private static byte checkRange(int value) {
        if (value < 0 || value > Byte.MAX_VALUE) {
            throw new IllegalArgumentException("Version component out of supported range (0-127)");
        }
        return (byte) value;
    }

    public Version(int major, int minor, int micro) {
        this(checkRange(major), checkRange(minor), checkRange(micro));
    }

    public Version(byte major, byte minor, byte micro) {
        this.major = major;
        this.minor = minor;
        this.micro = micro;
    }

    public byte[] getBytes() {
        return new byte[]{major, minor, micro};
    }

    private int compareToVersion(int major, int minor, int micro) {
        return Integer.compare(this.major << 16 | this.minor << 8 | this.micro, major << 16 | minor << 8 | micro);
    }

    @Override
    public int compareTo(Version other) {
        return compareToVersion(other.major, other.minor, other.micro);
    }

    public boolean isLessThan(int major, int minor, int micro) {
        return compareToVersion(major, minor, micro) < 0;
    }

    public boolean isAtLeast(int major, int minor, int micro) {
        return compareToVersion(major, minor, micro) >= 0;
    }

    public void requireAtLeast(int major, int minor, int micro) {
        if (major != 0 && isLessThan(major, minor, micro)) {
            throw new NotSupportedException(String.format("This action requires YubiKey %s or later", new Version(major, minor, micro)));
        }
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Version version = (Version) o;
        return major == version.major &&
                minor == version.minor &&
                micro == version.micro;
    }

    @Override
    public int hashCode() {
        return Objects.hash(major, minor, micro);
    }

    @Override
    public String toString() {
        return String.format(Locale.ROOT, "%d.%d.%d", 0xff & major, 0xff & minor, 0xff & micro);
    }

    public static Version fromBytes(byte[] bytes) {
        if (bytes.length < 3) {
            throw new IllegalArgumentException("Version byte array must contain 3 bytes.");
        }

        return new Version(bytes[0], bytes[1], bytes[2]);
    }

    /**
     * Parses from string format "Firmware version 5.2.1"
     *
     * @param nameAndVersion string that contains a 3-number version.
     * @return the firmware version
     */
    public static Version parse(String nameAndVersion) {
        Matcher match = VERSION_STRING_PATTERN.matcher(nameAndVersion);
        if (match.find()) {
            return new Version(
                    Byte.parseByte(match.group(1)),
                    Byte.parseByte(match.group(2)),
                    Byte.parseByte(match.group(3))
            );
        }
        throw new IllegalArgumentException("Invalid version string");
    }
}

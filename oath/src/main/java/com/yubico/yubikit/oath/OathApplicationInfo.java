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

package com.yubico.yubikit.oath;

import com.yubico.yubikit.utils.TlvUtils;
import com.yubico.yubikit.utils.Version;

import org.apache.commons.codec.binary.Base64;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Map;

/**
 * Result of SELECT OATH operation.
 * Contains version, ID and a challenge if authentication is configured
 */
public class OathApplicationInfo {

    private static final int TAG_NAME = 0x71;
    private static final int TAG_CHALLENGE = 0x74;
    private static final int TAG_VERSION = 0x79;

    private final Version version;
    private final byte[] salt;
    private final byte[] challenge;
    private final String deviceId;

    /**
     * Creates an instance of OATH application info from SELECT response
     * @param response the response from OATH SELECT command
     */
    OathApplicationInfo(byte[] response) {
        Map<Integer, byte[]> map = TlvUtils.parseTlvMap(response);
        version = Version.parse(map.get(TAG_VERSION));
        salt = map.get(TAG_NAME);
        challenge = map.get(TAG_CHALLENGE);
        deviceId = getDeviceIdString(salt);
    }

    /**
     * @return versions of firmware
     */
    public Version getVersion() {
        return version;
    }

    /**
     * @return device identifier
     */
    public String getDeviceId() {
        return deviceId;
    }

    /**
     * @return device salt
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * A challenge is returned if the authentication object is set. In that case an authentication is required for all commands except VALIDATE and RESET.
     * @return challenge
     */
    public byte[] getChallenge() {
        return challenge;
    }

    /**
     * @return true if the authentication object set and challenge is returned
     */
    public boolean isAuthenticationRequired() {
        return challenge != null && challenge.length != 0;
    }

    private static String getDeviceIdString(byte[] salt) {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            // Shouldn't happen.
            throw new IllegalStateException(e);
        }
        messageDigest.update(salt);
        byte[] digest = messageDigest.digest();
        return Base64.encodeBase64String(Arrays.copyOfRange(digest, 0, 16)).replaceAll("=", "");
    }
}

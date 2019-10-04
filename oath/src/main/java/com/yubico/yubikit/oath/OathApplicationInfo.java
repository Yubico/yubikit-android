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

import android.util.Base64;
import android.util.SparseArray;

import com.yubico.yubikit.apdu.ApduException;
import com.yubico.yubikit.apdu.Tlv;
import com.yubico.yubikit.apdu.TlvUtils;
import com.yubico.yubikit.apdu.Version;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Result of SELECT OATH operation.
 * Contains version, ID and a challenge if authentication is configured
 */
public class OathApplicationInfo {

    private static final byte TAG_NAME = 0x71;
    private static final byte TAG_CHALLENGE = 0x74;
    private static final byte TAG_VERSION = 0x79;

    private Version version;
    private byte[] deviceId;
    private byte[] challenge;

    /**
     * Creates an instance of OATH application info from SELECT response
     * @param response the response from OATH SELECT command
     */
    OathApplicationInfo(byte[] response) {
        SparseArray<byte[]> map = TlvUtils.parseTlvMap(response);
        version = Version.parse(map.get(TAG_VERSION));
        deviceId = map.get(TAG_NAME);
        challenge = map.get(TAG_CHALLENGE);
    }

    /**
     * @return versions of firmware
     */
    public Version getVersion() {
        return version;
    }

    /**
     * @return device id/name
     */
    public byte[] getDeviceId() {
        return deviceId;
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

    /**
     * @return device id hash string
     * @throws NoSuchAlgorithmException if SHA256 is not found
     */
    public String getDeviceIdString() throws NoSuchAlgorithmException {
        MessageDigest messageDigest = null;
        messageDigest = MessageDigest.getInstance("SHA256");
        messageDigest.update(deviceId);
        byte[] digest = messageDigest.digest();
        return Base64.encodeToString(Arrays.copyOfRange(digest, 0, 16), Base64.NO_PADDING | Base64.NO_WRAP);
    }
}

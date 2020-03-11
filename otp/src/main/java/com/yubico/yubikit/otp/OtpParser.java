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

package com.yubico.yubikit.otp;

import android.net.Uri;
import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.Tag;
import android.nfc.tech.Ndef;
import android.view.KeyCharacterMap;
import android.view.KeyEvent;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Parser that helps to extract OTP from nfc tag
 */
public class OtpParser {
    private static final String YUBICO_HOST_NAME = "my.yubico.com";

    private static final byte TYPE_URI = 0x55;
    private static final byte TYPE_TEXT = 0x54;

    /**
     *  Modhex mapping: https://developers.yubico.com/yubico-c/Manuals/modhex.1.html
     *  Used for OTP codes encoding
     */
    private static final String MODHEX_ALPHABET = "cbdefghijklnrtuv";
    private static final String OTP_MODHEX_PATTERN = "([" + MODHEX_ALPHABET + "]{32,64})";

    private static final String OTP_HOTP_NUMERIC_PATTERN = "([\\d]{6,8})";

    /**
     * HID to Android Keyboard key events mapping:
     * https://source.android.com/devices/input/keyboard-devices
     * Used for encoding of other types of data sent via OTP application
     */
    private static final int[] USB_HID_KEYBOARD = new int[] {
            0,  0,  0,  0, 0x1d, 0x1e, 0x1f, 0x20, 0x20, 0x22, 0x22, 0x24, 0x25, 0x26, 0x26, 0x28, //0x0f
        0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x08, 0x09, //0x1f
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x07, 0x42, 0x6f, 0x43, 0x3d, 0x3e, 0x45, 0x46, 0x47, //0x2f
        0x48, 0x49, 0x49, 0x4a, 0x4b, 0x44 ,0x37, 0x38, 0x4c, 0x73, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, // 0x3f
        0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x78, 0x74, 0x79, 0x7c, 0x7a, 0x5c, 0x70, 0x7b, 0x5d, 0x16, //0x4f
        0x15, 0x14, 0x13, 0x8f, 0x9a, 0x9b, 0x9c, 0x9d, 0xa0, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, //0x5f
        0x98, 0x99, 0x90, 0x9e, 0x49,0x52,0x1a,0xa1,0,0,0,0,0,0,0,0, //0x6f
            0,0,0,0,0,0,0,0,0x56,0,0,0,0,0,0,0xa4, //0x7f
        0x18, 0x19,  0,  0,  0,0x9f, 0, 0, 0,0, 0, 0, 0,  0,  0,  0, //0x8f
            0,0, 0, 0, 0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, //0x9f
            0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, //0xaf
            0,  0,  0,  0,  0,  0,  0xa2,  0xa3,  0,  0,  0,  0,  0,  0,  0,  0, //0xbf
            0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, //0xcf
            0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, //0xdf
        0x71, 0x3b, 0x39,0x75, 0x72, 0x3c, 0x3a, 0x76, 0x55, 0x56, 0x58, 0x57, 0x81, 0x18, 0x19, 0xa4, //0xef
        0x40, 0x04, 0x7d, 0x56, 0, 0x5c, 0x5d, 0, 0, 0x1a, 0, 0xd2 //0xff NOTE:last line is not used in yubi keyboard, first bit is used to show SHIFT_ON state
    };

    /**
     * Parses nfc tag and extracts otp credential from it
     * @param tag an NDEF compatible tag
     * @return OTP data
     * @throws ParseTagException if tag has no NDEF Tag Technology or there is no YK OTP payload
     */
    public static @NonNull String parseTag(Tag tag) throws ParseTagException {
        Ndef ndef = Ndef.get(tag);
        if (ndef == null) {
            throw new ParseTagException("Tag is not NDEF formatted");
        }
        NdefMessage message;
        try {
            ndef.connect();
            message = ndef.getNdefMessage();
        } catch (FormatException | IOException e) {
            message = ndef.getCachedNdefMessage();
        } finally {
            try {
                ndef.close();
            } catch (IOException ignore) {
            }
        }

        if (message == null) {
            throw new ParseTagException("Couldn't read ndef message");
        }

        String parsedData = parseNdefMessage(message);
        if (parsedData != null) {
            return parsedData;
        }
        throw new ParseTagException("Tag doesn't have YK OTP payload");
    }

    /**
     * Parses nfc tag and extracts otp credential from it
     * @param ndefMessage an NDEF message from tag
     * @return OTP data
     * @throws ParseTagException if tag has no NDEF Tag Technology or there is no YK OTP payload
     */
    public static @Nullable String parseNdefMessage(NdefMessage ndefMessage) throws ParseTagException {
        for (NdefRecord record : ndefMessage.getRecords()) {
            String parsedData = parseNdefRecord(record);
            if (parsedData != null) {
                return parsedData;
            }
        }
        return null;
    }

    public static @Nullable String parseUri(@NonNull Uri uri) {
        if (uri.getScheme() == null) {
            return null;
        }

        final UriFormat format = getFormat(uri);

        String otpCode = null;
        if (format == UriFormat.YK_5) {
            otpCode = uri.getFragment();
        } else if (format == UriFormat.YK_NEO) {
            otpCode = uri.getLastPathSegment();
        } else {
            return null;
        }

        // if there is nothing in payload (only scheme and prefix) than otpCode data is empty
        // without this check we might take last path segment of YK_NEO format (/neo)
        if (uri.toString().length() == uri.getScheme().length() + format.prefix.length() + "://".length()) {
            otpCode = "";
        }

        if (otpCode != null) {
            if (otpCode.matches(OTP_MODHEX_PATTERN)) {
                // default OTP Application (NDEF tag) set up on the key is YK OTP
                // https://developers.yubico.com/OTP/
                return otpCode;
            } else if (otpCode.matches(OTP_HOTP_NUMERIC_PATTERN)) {
                // HOTP
                return otpCode;
            } else {
                // static password or HOTP (8 digits HOTP also using scan codes)
                // use Yubico Manager to set up your key to return static password or HOTP
                return parseKeyboardCodes(otpCode.getBytes());
            }
        }
        return null;
    }


    /**
     * Parse ndef record if it provides uri or text
     * @param record ndef record from ndef tag
     * @return OTP application code, HOTP code or static password
     */
    static @Nullable String parseNdefRecord(NdefRecord record) {
        // not valid record or payload
        if (record == null || record.getPayload() == null || record.getPayload().length == 0) {
            return null;
        }

        if (record.getType().length > 0 && record.getType()[0] == TYPE_URI) {
            Uri uri = record.toUri();
            return parseUri(uri);
        } else if (record.getType().length > 0 && record.getType()[0] == TYPE_TEXT){
            String payload = new String(record.getPayload(), StandardCharsets.UTF_8);
            // returning last item in path
            if (payload.contains("/")) {
                String[] parts = payload.split("/");
                return parts[parts.length - 1];
            } else {
                return payload;
            }
        }

        // unexpected type of record
        return null;
    }

    /**
     * In case of static password or HOTP yubikey returns HID codes which needs to be mapped to Android KeyEvent codes
     * Using KeyEvent codes KeyCharacterMap returns charecters
     * @param data part of payload from NDEF message that contains only otp data
     *             NOTE: Format of initial payload: first byte of payload is 0x04, then uri prefix and than data that contains otp
     * @return value without Uri prefix
     */
    private static String parseKeyboardCodes(byte[] data) {
        // For specific layouts and locales Android supports device specific key layout files with InputDevice
        // https://source.android.com/devices/input/key-character-map-files
        // but external peripheral can be attached only to the USB or Bluetooth bus (Not NFC)
        // So we're not using VIRTUAL_KEYBOARD and not real deviceId
        // Note: if we want to support another layout/locale, we will have to create our own KeyCharacterMap
        // or another mapping to convert key_event into unicode character
        KeyCharacterMap map = KeyCharacterMap.load(KeyCharacterMap.VIRTUAL_KEYBOARD);
        StringBuilder sb = new StringBuilder();
        for (byte hid_key_code : data) {
            // make unsigned byte value
            boolean shiftOn = (0x80 & hid_key_code) == 0x80;
            int code = 0x7f & hid_key_code;
            sb.append((char)map.get(USB_HID_KEYBOARD[code], shiftOn ? KeyEvent.META_SHIFT_ON : 0));
        }
        return sb.toString();
    }

    /**
     * Check the length of code prefix (usually it's
     * @param ndefUri message uri of ndef tag
     * @return type of uri
     */
    private static UriFormat getFormat(Uri ndefUri) {
        if (ndefUri != null && YUBICO_HOST_NAME.equalsIgnoreCase(ndefUri.getHost()) && ndefUri.getPath() != null) {
            if("/yk/".equals(ndefUri.getPath()) && ndefUri.getFragment() != null) {
                // Generally uri format is https://my.yubico.com/yk/#<payload>
                return UriFormat.YK_5;
            } else if (ndefUri.getPath().startsWith("/neo")) {
                // YubiKey NEO uses https://my.yubico.com/neo/<payload>
                return UriFormat.YK_NEO;
            }
        }
        return null;
    }

    /**
     * Uri format of YubiKey Ndef tag
     */
    private enum UriFormat {
        YK_NEO (YUBICO_HOST_NAME + "/neo/"),
        YK_5 (YUBICO_HOST_NAME + "/yk/#");

        private String prefix;
        UriFormat(String prefix) {
            this.prefix = prefix;
        }
    }
}

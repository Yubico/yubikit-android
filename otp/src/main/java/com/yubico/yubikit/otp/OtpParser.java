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

        for (NdefRecord record : message.getRecords()) {
            String parsedData = parseNdefRecord(record);
            if (parsedData != null) {
                return parsedData;
            }
        }
        throw new ParseTagException("Tag doesn't have YK OTP payload");
    }

    /**
     * Parse ndef record if it provides uri or text
     * @param record ndef record from ndef tag
     * @return OTP application code, HOTP code or static password
     */
    static @Nullable String parseNdefRecord(NdefRecord record) {
        return parseNdefRecord(record, ScanCodeCharacterMap.getKeyboardLayout());
    }

    static @Nullable String parseNdefRecord(NdefRecord record, KeyboardLayout keyboardLayout) {
        // not valid record or payload
        if (record == null || record.getPayload() == null || record.getPayload().length == 0) {
            return null;
        }

        if (record.getType().length > 0 && record.getType()[0] == TYPE_URI) {
            final UriFormat format = getFormat(record.toUri());
            final String otpCode = parseUri(format, record.toUri());
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
                    return parseKeyboardCodes(format, record.getPayload(), keyboardLayout);
                }
            }
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
     * Parses OTP code out of uri
     *
     * @param format what type of uri was received
     * @param ndefUri uri from NDEF message
     * @return YK OTP code
     */
    private static @Nullable String parseUri(UriFormat format, Uri ndefUri) {
        if (format == UriFormat.YK_5) {
            return ndefUri.getFragment();
        } else if (format == UriFormat.YK_NEO) {
            return ndefUri.getLastPathSegment();
        }
        return null;
    }

    /**
     * In case of static password or HOTP yubikey returns HID codes which needs to be mapped to Android KeyEvent codes
     * Using KeyEvent codes KeyCharacterMap returns charecters
     * @param format what type of uri was received
     * @param payload payload from NDEF message
     * @return value without Uri prefix
     */
    private static String parseKeyboardCodes(UriFormat format, byte[] payload, KeyboardLayout keyboardLayout) {
        // first byte of payload is 0x04, then uri prefix and than data that we want to retrieve
        byte[] data = Arrays.copyOfRange(payload, 1 + format.prefix.length(), payload.length);

        StringBuilder sb = new StringBuilder();
        for (byte hid_key_code : data) {
            // make unsigned byte value
            boolean shiftOn = (0x80 & hid_key_code) == 0x80;
            int code = 0x7f & hid_key_code;
            sb.append((char)keyboardLayout.get(code, shiftOn));
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

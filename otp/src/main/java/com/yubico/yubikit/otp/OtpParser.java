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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

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
        return parseTag(tag, KeyboardLayoutProvider.getKeyboardLayout());
    }

    /**
     * Parses nfc tag and extracts otp credential from it
     * @param tag an NDEF compatible tag
     * @param keyboardLayout provide your own ScanCode to Character mapping for static password parsing
     *                  or use the one that provided by library in KeyboardLayoutProvider.getKeyboardLayout()
     *                  in case if user wants to use other languages/layouts
     * @return OTP data
     * @throws ParseTagException if tag has no NDEF Tag Technology or there is no YK OTP payload
     */
    public static @NonNull String parseTag(Tag tag, KeyboardLayout keyboardLayout) throws ParseTagException {
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

        String parsedData = parseNdefMessage(message, keyboardLayout);
        if (parsedData != null) {
            return parsedData;
        }
        throw new ParseTagException("Tag doesn't have YK OTP payload");
    }

    /**
     * Parses nfc tag and extracts otp credential from it
     * @param ndefMessage an NDEF message from tag
     * @return OTP data
     */
    public static @Nullable String parseNdefMessage(NdefMessage ndefMessage) {
        return parseNdefMessage(ndefMessage, KeyboardLayoutProvider.getKeyboardLayout());
    }


    /**
     * Parses nfc tag and extracts otp credential from it
     * @param ndefMessage an NDEF message from tag
     * @param keyboardLayout provide your own ScanCode to Character mapping for static password parsing
     *                  or use the one that provided by library in KeyboardLayoutProvider.getKeyboardLayout()
     *                  in case if user wants to use other languages/layouts
     * @return OTP data
     */
    public static @Nullable String parseNdefMessage(NdefMessage ndefMessage, KeyboardLayout keyboardLayout) {
        for (NdefRecord record : ndefMessage.getRecords()) {
            String parsedData = parseNdefRecord(record, keyboardLayout);
            if (parsedData != null) {
                return parsedData;
            }
        }
        return null;
    }

    /**
     * Parses Uri from NDEF tag message and extracts otp credential from it
     * @param uri Generally uri format is https://my.yubico.com/yk/#
     * @return parsed OTP data (OTP, HOTP or static password)
     */
    public static @Nullable String parseUri(@NonNull Uri uri) {
        return parseUri(uri, KeyboardLayoutProvider.getKeyboardLayout());
    }

    /**
     * Parses Uri from NDEF tag message and extracts otp credential from it
     * @param uri uri Generally uri format is https://my.yubico.com/yk/#
     * @param keyboardLayout provide your own ScanCode to Character mapping for static password parsing
     *                  or use the one that provided by library in KeyboardLayoutProvider.getKeyboardLayout()
     *                  in case if user wants to use other languages/layouts
     * @return parsed OTP data (OTP, HOTP or static password)
     */
    public static @Nullable String parseUri(@NonNull Uri uri, KeyboardLayout keyboardLayout) {
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
                return parseKeyboardCodes(otpCode.getBytes(), keyboardLayout);
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
        return parseNdefRecord(record, KeyboardLayoutProvider.getKeyboardLayout());
    }

    static @Nullable String parseNdefRecord(NdefRecord record, KeyboardLayout keyboardLayout) {
        // not valid record or payload
        if (record == null || record.getPayload() == null || record.getPayload().length == 0) {
            return null;
        }

        if (record.getType().length > 0 && record.getType()[0] == TYPE_URI) {
            Uri uri = record.toUri();
            return parseUri(uri, keyboardLayout);
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
     * @param keyboardLayout provide your own ScanCode to Character mapping
     *                  or use the one that provided by library in KeyboardLayoutProvider.getKeyboardLayout()
     * @return value without Uri prefix
     */

    private static String parseKeyboardCodes(byte[] data, KeyboardLayout keyboardLayout) {
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

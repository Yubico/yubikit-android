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
     */
    public static @Nullable String parseNdefMessage(NdefMessage ndefMessage) {
        for (NdefRecord record : ndefMessage.getRecords()) {
            String parsedData = parseNdefRecord(record);
            if (parsedData != null) {
                return parsedData;
            }
        }
        return null;
    }

    /**
     * Parses Uri from NDEF tag message and extracts the payload of it.
     * @param uri uri Generally uri format is https://my.yubico.com/yk/#&lt;payload&gt;
     * @return parsed OTP payload
     */
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
            return "";
        }

        if (otpCode != null && otpCode.length() == 8) {
            // Some YubiKeys output 8 digit HOTP as scan codes, which need to be translated
            StringBuilder hotp = new StringBuilder();
            for (byte code : otpCode.getBytes()) {
                if (code >= 0x1e && code < 0x27) {
                    hotp.append(code - 0x1d);
                } else if (code == 0x27) {
                    hotp.append("0");
                } else {
                    // Unknown character, not HOTP.
                    return otpCode;
                }
            }
            return hotp.toString();
        }

        return otpCode;
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

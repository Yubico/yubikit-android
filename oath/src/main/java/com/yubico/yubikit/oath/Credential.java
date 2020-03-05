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
import android.net.Uri;
import android.text.TextUtils;
import android.util.Pair;

import androidx.annotation.Nullable;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Locale;
import java.util.Objects;

public class Credential implements Serializable {

    /**
     * Properties that identify credential
     */
    public final String name;
    private final int period;
    private final @Nullable String issuer;
    private final OathType oathType;

    /**
     * These properties are used to create credential on key
     * But can be unknown/not received from yubikey during enlisting or calculation
     */
    private HashAlgorithm hashAlgorithm;
    private byte[] secret;
    private int counter = 0;
    private int digits = 6;

    /**
     * Flag whether key touch is required for calculation
     */
    private boolean touch = false;

    /**
     * Flag whether code needs to be truncated to number of digits
     * Default is true
     */
    private boolean truncated = true;

    /**
     * Variation of code types:
     * 0x75 - TOTP full response
     * 0x76 - TOTP truncated response
     * 0x77 - HOTP
     * 0x7c - TOTP requires touch
     */
    private static final byte TYPE_HOTP = 0x77;
    private static final byte TYPE_TOUCH = 0x7c;

    /**
     * Variation of credential types tags: 0x71 (contains only name and issuer)
     * or 0x72 (contains hash algo + oath type in first byte, than name and issuer)
     */
    private static final byte TAG_NAME = 0x71;

    /**
     * Regex for hex string
     */
    private static final String HEX_PATTERN = "^[0-9a-fA-F]+$";

    /**
     * Prefix that used only to detect whether result from yubikey doesn't need to be truncated
     */
    private static final String NOT_TRUNCATED_CODE_PREFIX = "full_";

    /**
     * Default period for all TOTP codes
     */
    public static final int DEFAULT_PERIOD = 30;

    /**
     * Parse credential properties from uri
     * @param uri Uri that received from QR reader or manually from server that requires TOTP/HOTP
     * Format example: otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
     * @return Credential object that needs to be sent to yubikey to store and generate codes
     * @throws ParseUriException in case if Uri format is incorrect
     */
    public static Credential parseUri(Uri uri) throws ParseUriException {
        if (uri == null) {
            throw new IllegalArgumentException("Uri must be not null");
        }

        if (!uri.isHierarchical() || !"otpauth".equalsIgnoreCase(uri.getScheme())) {
            throw new ParseUriException("Uri scheme must be otpauth://");
        }

        String path = uri.getPath();
        if (TextUtils.isEmpty(path)) {
            throw new ParseUriException("Path must contain name");
        }

        Pair<String, String> nameAndIssuer = parseNameAndIssuer(path, uri.getQueryParameter("issuer"));
        String host = uri.getHost();
        OathType oathType = OathType.fromString(host);
        if (oathType == null) {
            throw new ParseUriException("Invalid or missing OATH algorithm");
        }

        HashAlgorithm hashAlgorithm = HashAlgorithm.fromString(uri.getQueryParameter("algorithm"));
        if (hashAlgorithm == null) {
            throw new ParseUriException("Invalid or HMAC algorithm");
        }

        byte[] secret = null;
        try {
            secret = decodeSecret(uri.getQueryParameter("secret"));
        } catch (DecoderException e) {
            
        }
        if (secret == null) {
            throw new ParseUriException("Secret must be base32 encoded or hex");
        }

        Integer digits = parseInt(uri.getQueryParameter("digits"), 6);
        if (digits == null || (digits != 6 && digits != 7 && digits != 8)) {
            throw new ParseUriException("Digits must be in range 6-8");
        }

        Integer period = parseInt(uri.getQueryParameter("period"), DEFAULT_PERIOD);
        if (period == null) {
            throw new ParseUriException("Invalid value for period");
        }

        Integer counter = parseInt(uri.getQueryParameter("counter"), 0);
        if (counter == null) {
            throw new ParseUriException("Invalid value for counter");
        }
        return new Credential(nameAndIssuer.first, oathType, hashAlgorithm, secret, digits, period, counter, nameAndIssuer.second);
    }

    /**
     * Creates instance of {@link Credential}
     * @param name the name/label
     * @param oathType TOTP or HOTP
     * @param hashAlgorithm SHA1, SHA265 or SHA 512
     * @param secret the key data
     * @param digits the number of digits in OATH code
     * @param period the period in seconds how long TOTP is valid
     * @param counter Imf for HOTP
     * @param issuer issuer name
     */
    public Credential(String name, OathType oathType, HashAlgorithm hashAlgorithm, byte[] secret, int digits, int period, int counter, String issuer) {
        this.name = name;
        this.oathType = oathType;
        this.hashAlgorithm = hashAlgorithm;
        this.secret = secret;
        this.digits = digits;
        this.period = period;
        this.counter = counter;
        this.issuer = issuer;
    }

    /**
     * Creates instance of {@link Credential} from data that received from yubikey.
     * If only list of credentials requested (not codes), than use {@link Credential(byte[], int)}
     * @param value tlv value of credential tlv
     * @param type tlv tag of credential tlv
     * @param codeValue tlv value of code tlv
     * @param codeType tlv tag of code tlv
     */
    Credential(byte[] value, int type, byte[] codeValue, int codeType) {
        String data;
        if (type == TAG_NAME) {
            data = new String(value, StandardCharsets.UTF_8);
            this.oathType = codeType == TYPE_HOTP ? OathType.HOTP : OathType.TOTP;
            this.touch = codeType == TYPE_TOUCH;
        } else {
            this.oathType = OathType.fromValue((byte) (0xf0 & value[0]));
            this.hashAlgorithm = HashAlgorithm.fromValue((byte) (0x0f & value[0]));
            data = new String(Arrays.copyOfRange(value, 1, value.length), StandardCharsets.UTF_8);
        }

        if (data.contains("/")) {
            String[] parts = data.split("/",  2);
            Integer periodInt = parseInt(parts[0], DEFAULT_PERIOD);
            if (periodInt != null) {
                data = parts[1];
                period = periodInt;
            } else {
                period = DEFAULT_PERIOD;
            }
        } else {
            period = DEFAULT_PERIOD;
        }

        if (data.contains(":")) {
            Pair<String, String> nameAndIssuer = parseNameAndIssuer(data, null);
            name = nameAndIssuer.first;
            issuer = nameAndIssuer.second;
        } else {
            name = data;
            issuer = null;
        }

        if (codeValue != null && codeValue.length > 0) {
            digits = codeValue[0];
        }
    }

    /**
     * Creates instance of {@link Credential} from data that received from yubikey.
     * @param value tlv value
     * @param type tlv tag
     */
    Credential(byte[] value, int type) {
        this(value, type, null, 0);
    }

    /**
     * Sets flag that credential requires touch. Use it when create new Credential and user specified that calculation requires touch
     * @param touch true if requires touch, default is false
     */
    public void setTouch(boolean touch) {
        this.touch = touch;
    }

    /**
     * Sets flag that calculated code needs to be truncated to number of digits
     * @param truncate true if needs to be truncated, default is true
     */
    public void setTruncated(boolean truncate) {
        this.truncated = truncate;
    }

    /**
     * Gets name of credential that used as unique identifier
     * @return oathtype + issuer + name
     */
    public String getId() {
        String longName = "";
        if (oathType == OathType.TOTP && period != DEFAULT_PERIOD) {
            longName += String.format(Locale.ROOT,"%d/", period);
        }

        if (issuer != null) {
            longName += String.format(Locale.ROOT,"%s:", issuer);
        }
        longName += name;
        return longName;
    }

    /**
     * Oath type {@link OathType}
     * @return HOTP or TOTP
     */
    public OathType getOathType() {
        return oathType;
    }

    /**
     * Hash algorithm {@link HashAlgorithm}
     * @return SHA1, SHA256, SHA512
     */
    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Secret that is going to be hashed with hashAlgorithm
     * @return the secret
     */
    public byte[] getSecret() {
        return secret;
    }

    /**
     * Name of credential issuer (e.g. Google, Amazon, Facebook, etc)
     * @return the issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Number of digits that going to be used for code (value: 6,7 or 8)
     * @return number of digits in code
     */
    public int getDigits() {
        return digits;
    }

    /**
     * Period in seconds for how long code is valid from its calculation/generation time
     * @return the period (in seconds)
     */
    public int getPeriod() {
        return period;
    }

    /**
     * Initial counter (for HOTP) , default is 0
     * @return the counter
     */
    public int getCounter() {
        return counter;
    }

    /**
     * @return true if calculation requires touch on yubikey button
     */
    public boolean isTouch() {
        return touch;
    }

    /**
     * @return true if calculated code needs to be truncated
     */
    public boolean isTruncated() {
        return truncated;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Credential that = (Credential) o;
        return getId().equals(that.getId()) && oathType == that.oathType;
    }

    @Override
    public int hashCode() {
        return Objects.hash(getId(), oathType);
    }

    /**
     * Parses name and issuer from string value (url and tlv)
     * @param string UTF-8 string from key or qr code
     * @param defaultIssuer issuer name that could be obtained from another source
     * @return pair of name and issuer
     */
    private static Pair<String, String> parseNameAndIssuer(String string, String defaultIssuer) {
        if (string.startsWith("/")) {
            string = string.substring(1);
        }
        if (string.length() > 64) {
            string = string.substring(0, 64);
        }

        String issuer;
        if (string.contains(":")) {
            String[] parts = string.split(":", 2);
            string = parts[1];
            issuer = parts[0];
        } else {
            issuer = defaultIssuer;
        }

        String name = string;
        return new Pair<>(name, issuer);
    }

    /**
     * Parses int from value and provides default value in case provided value is empty
     * @param value int value as string (can be emtpy)
     * @param defaultValue default value in case provided value is empty
     * @return int or null in case if not number was provided in string value
     */
    private static Integer parseInt(String value, int defaultValue) {
        Integer result = defaultValue;
        if(!TextUtils.isEmpty(value)) {
            value = value.replaceAll("\\+", "");
            try {
                result = Integer.parseInt(value);
            } catch (NumberFormatException ignore) {
                return null;
            }
        }
        return result;
    }

    /**
     * Makes sure that secret is Base32 encoded and decodes it
     * @param secret string that contains Base32 encoded secret
     * @return decoded secret in byte array
     * @throws DecoderException in case of not proper format
     */
    public static byte[] decodeSecret(String secret) throws DecoderException {
        if (secret == null) {
            return null;
        }
        secret = secret.toUpperCase();
        Base32 base32 = new Base32();
        // most of secrets are base 32 encoded
        if (base32.isInAlphabet(secret)) {
            return base32.decode(secret);
        }
        // check if string is hex encoded
        if (secret.matches(HEX_PATTERN)) {
            return Hex.decodeHex(secret.toCharArray());
        }

        throw new DecoderException("secret must be base32 encoded or hex");
    }
}

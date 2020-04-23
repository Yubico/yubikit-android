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

package com.yubico.yubikit.oath;

import android.net.Uri;
import android.text.TextUtils;
import android.util.Pair;

import androidx.annotation.Nullable;

import org.apache.commons.codec.binary.Base32;

import java.io.Serializable;
import java.util.Arrays;
import java.util.Objects;

public class CredentialData implements Serializable {
    private final int period;
    private final OathType oathType;
    private final HashAlgorithm hashAlgorithm;
    private final byte[] secret;
    private final int counter;
    private final int digits;

    // User-modifiable fields
    @Nullable
    private String issuer;
    private String name;
    private boolean touchRequired = false;

    public static final int DEFAULT_PERIOD = 30;
    public static final int DEFAULT_DIGITS = 6;
    private static final int DEFAULT_COUNTER = 0;

    /**
     * Parse credential properties from an otpauth:// URI, as specified by
     * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
     * Format example: otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example
     *
     * @param uri Uri that received from QR reader or manually from server that requires TOTP/HOTP
     * @return Credential object that needs to be sent to yubikey to store and generate codes
     * @throws ParseUriException in case if Uri format is incorrect
     */
    public static CredentialData parseUri(Uri uri) throws ParseUriException {
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

        OathType oathType;
        try {
            oathType = OathType.fromString(uri.getHost());
        } catch (IllegalArgumentException e) {
            throw new ParseUriException("Invalid or missing OATH algorithm");
        }

        HashAlgorithm hashAlgorithm;
        try {
            hashAlgorithm = HashAlgorithm.fromString(uri.getQueryParameter("algorithm"));
        } catch (IllegalArgumentException e) {
            throw new ParseUriException("Invalid HMAC algorithm");
        }

        byte[] secret = decodeSecret(uri.getQueryParameter("secret"));

        int digits = getIntParam(uri, "digits", DEFAULT_DIGITS);
        if (digits < 6 || digits > 8) {
            throw new ParseUriException("digits must be in range 6-8");
        }

        int period = getIntParam(uri, "period", DEFAULT_PERIOD);
        int counter = getIntParam(uri, "counter", DEFAULT_COUNTER);

        return new CredentialData(nameAndIssuer.first, oathType, hashAlgorithm, secret, digits, period, counter, nameAndIssuer.second);
    }

    /**
     * Creates instance of {@link Credential}
     *
     * @param name          the name/label
     * @param oathType      TOTP or HOTP
     * @param hashAlgorithm SHA1, SHA265 or SHA 512
     * @param secret        the key data
     * @param digits        the number of digits in OATH code
     * @param period        the period in seconds how long TOTP is valid
     * @param counter       Imf for HOTP
     * @param issuer        issuer name
     */
    public CredentialData(String name, OathType oathType, HashAlgorithm hashAlgorithm, byte[] secret, int digits, int period, int counter, @Nullable String issuer) {
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
     * Set the issuer for the Credential, typically the name of the service.
     * @param issuer the name of the issuer.
     */
    public void setIssuer(@Nullable String issuer) {
        this.issuer = issuer;
    }

    /**
     * Set the name of the Credential, typically a username.
     * @param name the name of the Credential.
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * Sets flag that credential requires touch. Use it when create new Credential and user specified that calculation requires touch
     *
     * @param touchRequired true if requires touch, default is false
     */
    public void setTouchRequired(boolean touchRequired) {
        this.touchRequired = touchRequired;
    }

    /**
     * Get the name of the credential, typically a username.
     *
     * @return the name
     */
    public String getName() {
        return name;
    }

    /**
     * Gets name of credential that used as unique identifier
     *
     * @return [PERIOD/][ISSUER:]NAME
     */
    public byte[] getId() {
        return CredentialIdUtils.formatId(issuer, name, oathType, period);
    }

    /**
     * Oath type {@link OathType}
     *
     * @return HOTP or TOTP
     */
    public OathType getOathType() {
        return oathType;
    }

    /**
     * Hash algorithm {@link HashAlgorithm}
     *
     * @return SHA1, SHA256, SHA512
     */
    public HashAlgorithm getHashAlgorithm() {
        return hashAlgorithm;
    }

    /**
     * Secret that is going to be hashed with hashAlgorithm
     *
     * @return the secret
     */
    public byte[] getSecret() {
        return secret;
    }

    /**
     * Name of credential issuer (e.g. Google, Amazon, Facebook, etc)
     *
     * @return the issuer
     */
    public String getIssuer() {
        return issuer;
    }

    /**
     * Number of digits that going to be used for code (value: 6,7 or 8)
     *
     * @return number of digits in code
     */
    public int getDigits() {
        return digits;
    }

    /**
     * Period in seconds for how long code is valid from its calculation/generation time
     *
     * @return the period (in seconds)
     */
    public int getPeriod() {
        return period;
    }

    /**
     * Initial counter (for HOTP) , default is 0
     *
     * @return the counter
     */
    public int getCounter() {
        return counter;
    }

    /**
     * @return true if calculation requires touch on yubikey button
     */
    public boolean isTouchRequired() {
        return touchRequired;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        CredentialData that = (CredentialData) o;
        return period == that.period &&
                counter == that.counter &&
                digits == that.digits &&
                touchRequired == that.touchRequired &&
                Objects.equals(issuer, that.issuer) &&
                name.equals(that.name) &&
                oathType == that.oathType &&
                hashAlgorithm == that.hashAlgorithm &&
                Arrays.equals(secret, that.secret);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(issuer, name, period, oathType, hashAlgorithm, counter, digits, touchRequired);
        result = 31 * result + Arrays.hashCode(secret);
        return result;
    }

    /**
     * Parses name and issuer from string value from an otpauth:// URI.
     *
     * @param string        UTF-8 string from key or qr code
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
     * Parse an int from a Uri query parameter.
     *
     * @param uri Uri to get query parameter from.
     * @param name query parameter name.
     * @param defaultValue default value in case query paramater is omitted.
     * @return the parsed value, or the default value, if missing.
     * @throws ParseUriException if the value exists and is malformed.
     */
    private static int getIntParam(Uri uri, String name, int defaultValue) throws ParseUriException {
        String value = uri.getQueryParameter(name);
        int result = defaultValue;
        if (!TextUtils.isEmpty(value)) {
            value = value.replaceAll("\\+", "");
            try {
                result = Integer.parseInt(value);
            } catch (NumberFormatException ignore) {
                throw new ParseUriException(name + " is not a valid integer");
            }
        }
        return result;
    }

    /**
     * Makes sure that secret is Base32 encoded and decodes it
     *
     * @param secret string that contains Base32 encoded secret
     * @return decoded secret in byte array
     * @throws ParseUriException in case of not proper format
     */
    private static byte[] decodeSecret(String secret) throws ParseUriException {
        if (secret == null) {
            throw new ParseUriException("secret must not be null");
        }
        secret = secret.toUpperCase();
        Base32 base32 = new Base32();
        if (base32.isInAlphabet(secret)) {
            return base32.decode(secret);
        }

        throw new ParseUriException("secret must be base32 encoded");
    }
}

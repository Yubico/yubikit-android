/*
 * Copyright (C) 2020-2022 Yubico.
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

import com.yubico.yubikit.core.util.Pair;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

/** Data object holding all required information to add a new {@link Credential} to a YubiKey. */
public class CredentialData implements Serializable {
  /** The default time period for TOTP Credentials. */
  public static final int DEFAULT_TOTP_PERIOD = 30;

  /** The default number of digits for calculated {@link Code}s. */
  public static final int DEFAULT_DIGITS = 6;

  private static final int DEFAULT_HOTP_COUNTER = 0;

  private final int period;
  private final OathType oathType;
  private final HashAlgorithm hashAlgorithm;
  private final byte[] secret;
  private final int counter;
  private final int digits;

  // User-modifiable fields
  @Nullable private final String issuer;
  private final String accountName;

  /**
   * Parses an <a
   * href="https://github.com/google/google-authenticator/wiki/Key-Uri-Format">otpauth:// URI</a>.
   *
   * <p>Example URI:
   *
   * <pre>otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&amp;issuer=Example</pre>
   *
   * @param uri the otpauth:// URI to parse
   * @throws ParseUriException if the URI format is invalid
   */
  @SuppressWarnings("SpellCheckingInspection")
  public static CredentialData parseUri(URI uri) throws ParseUriException {
    if (!"otpauth".equals(uri.getScheme())) {
      throw new ParseUriException("Uri scheme must be otpauth://");
    }

    String path = uri.getPath();
    if (path.isEmpty()) {
      throw new ParseUriException("Path must contain name");
    }

    Map<String, String> params = new HashMap<>();
    String rawQuery = uri.getRawQuery();
    if (rawQuery == null || rawQuery.isEmpty()) {
      throw new ParseUriException("Query must contain parameters");
    }

    for (String line : rawQuery.split("&")) {
      String[] parts = line.split("=", 2);
      if (parts.length != 2) {
        throw new ParseUriException("Invalid query parameter: " + line);
      }
      String decodedValue = parts[1];
      try {
        decodedValue = URLDecoder.decode(decodedValue, "UTF-8");
      } catch (IllegalArgumentException e) {
        throw new ParseUriException("Invalid URL encoding in parameter value: " + decodedValue);
      } catch (UnsupportedEncodingException e) {
        throw new ParseUriException(
            "UTF-8 encoding not supported while parsing value: " + decodedValue);
      }

      params.put(parts[0], decodedValue);
    }

    Pair<String, String> nameAndIssuer = parseNameAndIssuer(path, params.get("issuer"));

    OathType oathType;
    try {
      oathType = OathType.fromString(uri.getHost());
    } catch (IllegalArgumentException e) {
      throw new ParseUriException("Invalid or missing OATH algorithm");
    }

    HashAlgorithm hashAlgorithm;
    String algorithmName = params.get("algorithm");
    if (algorithmName == null) {
      hashAlgorithm = HashAlgorithm.SHA1;
    } else {
      try {
        hashAlgorithm = HashAlgorithm.fromString(algorithmName);
      } catch (IllegalArgumentException e) {
        throw new ParseUriException("Invalid HMAC algorithm");
      }
    }

    String secretParam = params.get("secret");
    if (secretParam == null || secretParam.isEmpty()) {
      throw new ParseUriException("secret must be provided and not empty");
    }
    byte[] secret = decodeSecret(secretParam);

    int digits = getIntParam(params, "digits", DEFAULT_DIGITS);
    if (digits < 6 || digits > 8) {
      throw new ParseUriException("digits must be in range 6-8");
    }

    int period = getIntParam(params, "period", DEFAULT_TOTP_PERIOD);
    int counter = getIntParam(params, "counter", DEFAULT_HOTP_COUNTER);

    return new CredentialData(
        nameAndIssuer.first,
        oathType,
        hashAlgorithm,
        secret,
        digits,
        period,
        counter,
        nameAndIssuer.second);
  }

  /**
   * Constructs a new instance from the given parameters.
   *
   * @param accountName the name/label of the account, typically a username or email address
   * @param oathType the OATH type of the credential (TOTP or HOTP)
   * @param hashAlgorithm the hash algorithm used by the credential (SHA1, SHA265 or SHA 512)
   * @param secret the secret key of the credential, in raw bytes (<i>not</i> Base32 encoded)
   * @param digits the number of digits to display for generated {@link Code}s
   * @param period the validity period of generated {@link Code}s, in seconds, for a TOTP credential
   * @param counter the initial counter value (initial moving factor) for a HOTP credential
   *     (typically this should be 0)
   * @param issuer the name of the credential issuer (e.g. Google, Amazon, Facebook, etc.)
   */
  public CredentialData(
      String accountName,
      OathType oathType,
      HashAlgorithm hashAlgorithm,
      byte[] secret,
      int digits,
      int period,
      int counter,
      @Nullable String issuer) {
    this.accountName = accountName;
    this.oathType = oathType;
    this.hashAlgorithm = hashAlgorithm;
    this.secret = Arrays.copyOf(secret, secret.length);
    this.digits = digits;
    this.period = period;
    this.counter = counter;
    this.issuer = issuer;
  }

  /**
   * Returns the credentials ID, as used to identify it on a YubiKey.
   *
   * <p>The Credential ID is calculated based on the combination of the issuer, the name, and (for
   * TOTP credentials) the validity period.
   */
  public byte[] getId() {
    return CredentialIdUtils.formatId(issuer, accountName, oathType, period);
  }

  /** Returns the name of the credential. */
  public String getAccountName() {
    return accountName;
  }

  /** Returns the OATH type (HOTP or TOTP) of the credential. */
  public OathType getOathType() {
    return oathType;
  }

  /** Returns the hash algorithm used by the credential. */
  public HashAlgorithm getHashAlgorithm() {
    return hashAlgorithm;
  }

  /** Returns the credential secret. */
  public byte[] getSecret() {
    return Arrays.copyOf(secret, secret.length);
  }

  /** Returns the name of the credential issuer. */
  @Nullable
  public String getIssuer() {
    return issuer;
  }

  /**
   * Returns the number of digits in {@link Code}s calculated from the credential.
   *
   * @return number of digits in code
   */
  public int getDigits() {
    return digits;
  }

  /**
   * Returns the validity time period in seconds for a {@link Code} generated from this credential.
   */
  public int getPeriod() {
    return period;
  }

  /** Returns the initial counter value for a HOTP credential. */
  public int getCounter() {
    return counter;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    CredentialData that = (CredentialData) o;
    return period == that.period
        && counter == that.counter
        && digits == that.digits
        && Objects.equals(issuer, that.issuer)
        && accountName.equals(that.accountName)
        && oathType == that.oathType
        && hashAlgorithm == that.hashAlgorithm
        && Arrays.equals(secret, that.secret);
  }

  @Override
  public int hashCode() {
    int result =
        Objects.hash(issuer, accountName, period, oathType, hashAlgorithm, counter, digits);
    result = 31 * result + Arrays.hashCode(secret);
    return result;
  }

  /**
   * Parses name and issuer from string value from an otpauth:// URI.
   *
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
   * Parse an int from a Uri query parameter.
   *
   * @param params Query parameter map.
   * @param name query parameter name.
   * @param defaultValue default value in case query parameter is omitted.
   * @return the parsed value, or the default value, if missing.
   * @throws ParseUriException if the value exists and is malformed.
   */
  private static int getIntParam(Map<String, String> params, String name, int defaultValue)
      throws ParseUriException {
    String value = params.get(name);
    int result = defaultValue;
    if (!(value == null || value.isEmpty())) {
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
    secret = secret.toUpperCase();
    try {
      return Base32.decode(secret);
    } catch (IllegalArgumentException illegalArgumentException) {
      throw new ParseUriException("secret must be base32 encoded");
    }
  }
}

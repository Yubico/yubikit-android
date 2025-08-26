/*
 * Copyright (C) 2023-2025 Yubico.
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

package com.yubico.yubikit.openpgp;

import static com.yubico.yubikit.core.application.SessionVersionOverride.overrideOf;
import static com.yubico.yubikit.core.util.ByteUtils.intToLength;
import static com.yubico.yubikit.openpgp.OpenPgpUtils.decodeBcd;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.ApplicationSession;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.application.Feature;
import com.yubico.yubikit.core.application.InvalidPinException;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

/**
 * OpenPGP card application as specified on <a href="https://gnupg.org/ftp/specs/">gnupg.org</a>.
 *
 * <p>Enables you to manage keys and data, as well as perform signing, decryption, and
 * authentication operations.
 */
public class OpenPgpSession extends ApplicationSession<OpenPgpSession> {
  /** Support for factory reset. */
  public static final Feature<OpenPgpSession> FEATURE_RESET =
      new Feature.Versioned<>("Reset", 1, 0, 6);

  /** Support for the User Interaction Flag (touch requirement). */
  public static final Feature<OpenPgpSession> FEATURE_UIF = new Feature.Versioned<>("UIF", 4, 2, 0);

  /** Support for public key attestation. */
  public static final Feature<OpenPgpSession> FEATURE_ATTESTATION =
      new Feature.Versioned<>("Attestation", 5, 2, 1);

  /** Support for the "cached" UIF settings. */
  public static final Feature<OpenPgpSession> FEATURE_CACHED =
      new Feature.Versioned<>("Cached UIF", 5, 2, 1);

  /** Support for 4096 (and 3072) bit RSA keys, in addition to 2048-bit. */
  public static final Feature<OpenPgpSession> FEATURE_RSA4096_KEYS =
      new Feature.Versioned<>("RSA 4096 keys", 4, 0, 0);

  /** Support for private keys using Elliptic Curve cryptography. */
  public static final Feature<OpenPgpSession> FEATURE_EC_KEYS =
      new Feature.Versioned<>("Elliptic curve keys", 5, 2, 0);

  /** Support for resetting the PIN verified state. */
  public static final Feature<OpenPgpSession> FEATURE_UNVERIFY_PIN =
      new Feature.Versioned<>("Unverify PIN", 5, 6, 0);

  /** Support for changing the number of PIN attempts allowed before becoming blocked. */
  public static final Feature<OpenPgpSession> FEATURE_PIN_ATTEMPTS =
      new Feature<OpenPgpSession>("Set PIN attempts") {
        @Override
        public boolean isSupportedBy(Version version) {
          if (version.major == 1) {
            // YubiKey NEO
            return version.isAtLeast(1, 0, 7);
          }
          return version.isAtLeast(4, 3, 1);
        }
      };

  /** Support for generating RSA keys. */
  public static final Feature<OpenPgpSession> FEATURE_RSA_GENERATION =
      new Feature<OpenPgpSession>("RSA key generation") {
        @Override
        public boolean isSupportedBy(Version version) {
          return version.isLessThan(4, 2, 6) || version.isAtLeast(4, 3, 5);
        }
      };

  private static final byte INS_VERIFY = 0x20;
  private static final byte INS_CHANGE_PIN = 0x24;
  private static final byte INS_RESET_RETRY_COUNTER = 0x2c;
  private static final byte INS_PSO = 0x2A;
  private static final byte INS_ACTIVATE = 0x44;
  private static final byte INS_GENERATE_ASYM = 0x47;
  private static final byte INS_GET_CHALLENGE = (byte) 0x84;
  private static final byte INS_INTERNAL_AUTHENTICATE = (byte) 0x88;
  private static final byte INS_SELECT_DATA = (byte) 0xa5;
  private static final byte INS_GET_DATA = (byte) 0xca;
  private static final byte INS_PUT_DATA = (byte) 0xda;
  private static final byte INS_PUT_DATA_ODD = (byte) 0xdb;
  private static final byte INS_TERMINATE = (byte) 0xe6;
  private static final byte INS_GET_VERSION = (byte) 0xf1;
  private static final byte INS_SET_PIN_RETRIES = (byte) 0xf2;
  private static final byte INS_GET_ATTESTATION = (byte) 0xfb;

  private static final int TAG_PUBLIC_KEY = 0x7F49;

  private static final byte[] INVALID_PIN = new byte[8];

  private final SmartCardProtocol protocol;
  private final Version version;
  private final ApplicationRelatedData appData;

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(OpenPgpSession.class);

  /**
   * Create new instance of {@link OpenPgpSession} and selects the application for use.
   *
   * @param connection a smart card connection to a YubiKey
   * @throws IOException in case of communication error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws ApplicationNotAvailableException if the application is missing or disabled
   */
  public OpenPgpSession(SmartCardConnection connection)
      throws IOException, ApplicationNotAvailableException, ApduException {
    this(connection, null);
  }

  /**
   * Create new instance of {@link OpenPgpSession} and selects the application for use.
   *
   * @param connection a smart card connection to a YubiKey
   * @param scpKeyParams SCP key parameters to establish a secure connection
   * @throws IOException in case of communication error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws ApplicationNotAvailableException if the application is missing or disabled
   */
  public OpenPgpSession(SmartCardConnection connection, @Nullable ScpKeyParams scpKeyParams)
      throws IOException, ApplicationNotAvailableException, ApduException {
    protocol = new SmartCardProtocol(connection);

    try {
      protocol.select(AppId.OPENPGP);
    } catch (IOException e) {
      // The OpenPGP applet can be in an inactive state, in which case it needs activation.
      activate(e);
    }

    if (scpKeyParams != null) {
      try {
        protocol.initScp(scpKeyParams);
      } catch (BadResponseException e) {
        throw new IOException("Failed setting up SCP session", e);
      }
    }

    Logger.debug(logger, "Getting version number");
    byte[] versionBcd = protocol.sendAndReceive(new Apdu(0, INS_GET_VERSION, 0, 0, null));
    byte[] versionBytes = new byte[3];
    for (int i = 0; i < 3; i++) {
      versionBytes[i] = decodeBcd(versionBcd[i]);
    }
    version = overrideOf(Version.fromBytes(versionBytes));
    protocol.configure(version);

    // Note: This value is cached!
    // Do not rely on contained information that can change!
    appData = getApplicationRelatedData();

    Logger.debug(logger, "OpenPGP session initialized (version={})", version);
  }

  private void activate(IOException e)
      throws IOException, ApduException, ApplicationNotAvailableException {
    Throwable cause = e.getCause();
    if (cause instanceof ApduException) {
      short sw = ((ApduException) cause).getSw();
      if (sw == SW.NO_INPUT_DATA || sw == SW.CONDITIONS_NOT_SATISFIED) {
        // Not activated, activate
        Logger.warn(logger, "Application not active, sending ACTIVATE");
        protocol.sendAndReceive(new Apdu(0, INS_ACTIVATE, 0, 0, null));
        protocol.select(AppId.OPENPGP);
        return;
      }
    }
    throw e;
  }

  @Override
  public Version getVersion() {
    return version;
  }

  @Override
  public void close() throws IOException {
    protocol.close();
  }

  /**
   * Read a Data Object from the YubiKey.
   *
   * @param doId the ID of the Data Object to read
   * @return the value of the Data Object
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public byte[] getData(int doId) throws ApduException, IOException {
    Logger.debug(logger, "Reading Data Object {}", doId);
    return protocol.sendAndReceive(new Apdu(0, INS_GET_DATA, doId >> 8, doId & 0xff, null));
  }

  /**
   * Write a Data Object to the YubiKey.
   *
   * @param doId the ID of the Data Object to read
   * @param data the value to write to the Data Object
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void putData(int doId, byte[] data) throws ApduException, IOException {
    protocol.sendAndReceive(new Apdu(0, INS_PUT_DATA, doId >> 8, doId & 0xff, data));
    Logger.debug(logger, "Wrote Data Object {}", doId);
  }

  /**
   * Read the Application Related Data from the YubiKey.
   *
   * @return the parsed Application Related Data
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public ApplicationRelatedData getApplicationRelatedData() throws ApduException, IOException {
    return ApplicationRelatedData.parse(getData(Do.APPLICATION_RELATED_DATA));
  }

  /**
   * Get the AID for the OpenPGP application.
   *
   * @return the parsed OpenPgpAid
   */
  public OpenPgpAid getAid() {
    return appData.getAid();
  }

  /**
   * Get the Extended Capabilities supported by the YubiKey.
   *
   * @return the parsed ExtendedCapabilities
   */
  public ExtendedCapabilities getExtendedCapabilities() {
    return appData.getDiscretionary().getExtendedCapabilities();
  }

  /**
   * Get the current PIN configuration and status from the YubiKey.
   *
   * @return a PwStatus object with remaining attempts, maximum PIN lengths, and signature PIN
   *     policy
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public PwStatus getPinStatus() throws ApduException, IOException {
    return PwStatus.parse(getData(Do.PW_STATUS_BYTES));
  }

  /**
   * Read the current KDF settings configured for the YubiKey.
   *
   * @return a Kdf object, capable of deriving a key from a PIN
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public Kdf getKdf() throws ApduException, IOException {
    ExtendedCapabilities capabilities = getExtendedCapabilities();
    if (!capabilities.getFlags().contains(ExtendedCapabilityFlag.KDF)) {
      return new Kdf.None();
    }
    return Kdf.parse(getData(Do.KDF));
  }

  /**
   * Set up a PIN Key Derivation Function.
   *
   * <p>This enables (or disables) the use of a KDF for PIN verification, as well as resetting the
   * User and Admin PINs to their default (initial) values.
   *
   * <p>If a Reset Code is present, it will be invalidated.
   *
   * <p>This command requires Admin PIN verification.
   *
   * @param kdf the KDF configuration to set
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void setKdf(Kdf kdf) throws ApduException, IOException {
    ExtendedCapabilities capabilities = getExtendedCapabilities();
    if (!capabilities.getFlags().contains(ExtendedCapabilityFlag.KDF)) {
      throw new UnsupportedOperationException("KDF is not supported");
    }

    Logger.debug(logger, "Setting PIN KDF to algorithm: {}", kdf.getAlgorithm());
    putData(Do.KDF, kdf.getBytes());
    Logger.info(logger, "KDF settings changed");
  }

  private void doVerify(Pw pw, char[] pin, byte mode)
      throws ApduException, IOException, InvalidPinException {
    byte[] pinEnc = getKdf().process(pw, pin);
    try {
      protocol.sendAndReceive(new Apdu(0, INS_VERIFY, 0, pw.getValue() + mode, pinEnc));
    } catch (ApduException e) {
      if (e.getSw() == SW.SECURITY_CONDITION_NOT_SATISFIED) {
        int remaining = getPinStatus().getAttempts(pw);
        throw new InvalidPinException(remaining);
      } else if (e.getSw() == SW.AUTH_METHOD_BLOCKED) {
        throw new InvalidPinException(0, pw.name() + " PIN blocked");
      }
      throw e;
    } finally {
      Arrays.fill(pinEnc, (byte) 0);
    }
  }

  /**
   * Verify the User PIN.
   *
   * <p>This will unlock functionality that requires User PIN verification. Note that with
   * extended=false only sign operations are allowed. Inversely, with extended=true sign operations
   * are NOT allowed.
   *
   * @param pin the User PIN to verify
   * @param extended false to verify for signature use, true for other uses
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   * @throws InvalidPinException in case of the wrong PIN
   */
  public void verifyUserPin(char[] pin, boolean extended)
      throws ApduException, IOException, InvalidPinException {
    doVerify(Pw.USER, pin, extended ? (byte) 1 : 0);
  }

  /**
   * Verify the Admin PIN.
   *
   * <p>This will unlock functionality that requires Admin PIN verification.
   *
   * @param pin the Admin PIN to verify
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   * @throws InvalidPinException in case of the wrong PIN
   */
  public void verifyAdminPin(char[] pin) throws ApduException, IOException, InvalidPinException {
    doVerify(Pw.ADMIN, pin, (byte) 0);
  }

  private void doUnverifyPin(Pw pw) throws ApduException, IOException {
    require(FEATURE_UNVERIFY_PIN);
    Logger.debug(logger, "Resetting verification for {} PIN", pw.name());
    protocol.sendAndReceive(new Apdu(0, INS_VERIFY, 0xff, pw.getValue(), null));
    Logger.info(logger, "{} PIN unverified", pw.name());
  }

  /**
   * Resets the verification state of the User PIN to unverified.
   *
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void unverifyUserPin() throws ApduException, IOException {
    doUnverifyPin(Pw.USER);
  }

  /**
   * Resets the verification state of the Admin PIN to unverified.
   *
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void unverifyAdminPin() throws ApduException, IOException {
    doUnverifyPin(Pw.ADMIN);
  }

  /**
   * Gets the number of signatures performed with the SIG key.
   *
   * @return the number of signatures
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public int getSignatureCounter() throws ApduException, IOException {
    return SecuritySupportTemplate.parse(getData(Do.SECURITY_SUPPORT_TEMPLATE))
        .getSignatureCounter();
  }

  /**
   * Generate random data on the YubiKey.
   *
   * @param length the number of bytes to generate
   * @return random data of the given length
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public byte[] getChallenge(int length) throws ApduException, IOException {
    ExtendedCapabilities capabilities = getExtendedCapabilities();
    if (!capabilities.getFlags().contains(ExtendedCapabilityFlag.GET_CHALLENGE)) {
      throw new UnsupportedOperationException("GET_CHALLENGE is not supported");
    }
    if (length < 0 || length > capabilities.getChallengeMaxLength()) {
      throw new UnsupportedOperationException("Unsupported challenge length");
    }

    Logger.debug(logger, "Getting {} random bytes", length);
    return protocol.sendAndReceive(new Apdu(0, INS_GET_CHALLENGE, 0, 0, null, length));
  }

  /**
   * Set the PIN policy for the signature key slot.
   *
   * <p>A PIN policy of ONCE (the default) requires the User PIN to be verified once per session
   * prior to creating a signature. A policy of ALWAYS requires a new PIN verification prior to each
   * signature made.
   *
   * @param pinPolicy the PIN policy to set
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void setSignaturePinPolicy(PinPolicy pinPolicy) throws ApduException, IOException {
    Logger.debug(logger, "Setting Signature PIN policy to {}", pinPolicy);
    putData(Do.PW_STATUS_BYTES, new byte[] {pinPolicy.value});
    Logger.info(logger, "Signature PIN policy set");
  }

  /**
   * Performs a factory reset on the OpenPGP application.
   *
   * <p>WARNING: This will delete all stored keys, certificates and other data.
   *
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void reset() throws ApduException, IOException {
    require(FEATURE_RESET);
    Logger.debug(logger, "Preparing OpenPGP reset");

    // Ensure the User and Admin PINs are blocked
    PwStatus status = getPinStatus();
    for (Pw pw : Arrays.asList(Pw.USER, Pw.ADMIN)) {
      Logger.debug(logger, "Verify {} PIN with invalid attempts until blocked", pw);
      for (int i = status.getAttempts(pw); i > 0; i--) {
        try {
          protocol.sendAndReceive(new Apdu(0, INS_VERIFY, 0, pw.getValue(), INVALID_PIN));
        } catch (ApduException e) {
          // Ignore
        }
      }
    }

    // Reset the application
    Logger.debug(logger, "Sending TERMINATE, then ACTIVATE");
    protocol.sendAndReceive(new Apdu(0, INS_TERMINATE, 0, 0, null));
    protocol.sendAndReceive(new Apdu(0, INS_ACTIVATE, 0, 0, null));
    Logger.info(logger, "OpenPGP application data reset performed");
  }

  /**
   * Set the number of PIN attempts to allow before blocking.
   *
   * <p>WARNING: On YubiKey NEO this will reset the PINs to their default values.
   *
   * <p>Requires Admin PIN verification.
   *
   * @param userAttempts the number of attempts for the User PIN
   * @param resetAttempts the number of attempts for the Reset Code
   * @param adminAttempts the number of attempts for the Admin PIN
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void setPinAttempts(int userAttempts, int resetAttempts, int adminAttempts)
      throws ApduException, IOException {
    require(FEATURE_PIN_ATTEMPTS);

    Logger.debug(
        logger, "Setting PIN attempts to ({}, {}, {})", userAttempts, resetAttempts, adminAttempts);
    protocol.sendAndReceive(
        new Apdu(
            0,
            INS_SET_PIN_RETRIES,
            0,
            0,
            new byte[] {(byte) userAttempts, (byte) resetAttempts, (byte) adminAttempts}));
    Logger.info(logger, "Number of PIN attempts has been changed");
  }

  private void changePw(Pw pw, char[] pin, char[] newPin)
      throws ApduException, IOException, InvalidPinException {
    Logger.debug(logger, "Changing {} PIN", pw);
    Kdf kdf = getKdf();
    byte[] pinBytes = null;
    byte[] newPinBytes = null;
    byte[] data = null;
    try {
      pinBytes = kdf.process(pw, pin);
      newPinBytes = kdf.process(pw, newPin);
      data =
          ByteBuffer.allocate(pinBytes.length + newPinBytes.length)
              .put(pinBytes)
              .put(newPinBytes)
              .array();
      protocol.sendAndReceive(new Apdu(0, INS_CHANGE_PIN, 0, pw.getValue(), data));

    } catch (ApduException e) {
      if (e.getSw() == SW.SECURITY_CONDITION_NOT_SATISFIED) {
        int remaining = getPinStatus().getAttempts(pw);
        throw new InvalidPinException(remaining);
      }
      throw e;
    } finally {
      if (data != null) {
        Arrays.fill(data, (byte) 0);
      }
      if (pinBytes != null) {
        Arrays.fill(pinBytes, (byte) 0);
      }
      if (newPinBytes != null) {
        Arrays.fill(newPinBytes, (byte) 0);
      }
    }
    Logger.info(logger, "New {} PIN set", pw);
  }

  /**
   * Change the User PIN.
   *
   * @param pin the current User PIN
   * @param newPin the new User PIN to set
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   * @throws InvalidPinException in case of the wrong PIN in case of the wrong PIN
   */
  public void changeUserPin(char[] pin, char[] newPin)
      throws ApduException, IOException, InvalidPinException {
    changePw(Pw.USER, pin, newPin);
  }

  /**
   * Change the Admin PIN.
   *
   * @param pin the current Admin PIN
   * @param newPin the new Admin PIN to set
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   * @throws InvalidPinException in case of the wrong PIN
   */
  public void changeAdminPin(char[] pin, char[] newPin)
      throws ApduException, IOException, InvalidPinException {
    changePw(Pw.ADMIN, pin, newPin);
  }

  /**
   * Set the Reset Code for User PIN.
   *
   * <p>The Reset Code can be used to set a new User PIN if it is lost or becomes blocked, using the
   * reset_pin method.
   *
   * <p>This command requires Admin PIN verification.
   *
   * @param resetCode the Reset Code to set
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void setResetCode(char[] resetCode) throws ApduException, IOException {
    Logger.debug(logger, "Setting a new PIN Reset Code");
    byte[] data = null;
    try {
      data = getKdf().process(Pw.RESET, resetCode);
      putData(Do.RESETTING_CODE, data);
    } finally {
      if (data != null) {
        Arrays.fill(data, (byte) 0);
      }
    }

    Logger.info(logger, "New Reset Code has been set");
  }

  /**
   * Resets the User PIN in case it is lost or blocked.
   *
   * <p>This can be done either after performing Admin PIN verification, or by providing the Reset
   * Code.
   *
   * <p>This command requires Admin PIN verification, or the Reset Code.
   *
   * @param newPin the new User PIN to set
   * @param resetCode the Reset Code, which is needed if the Admin pin has not been verified
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   * @throws InvalidPinException in case of the wrong PIN
   */
  public void resetPin(char[] newPin, @Nullable char[] resetCode)
      throws ApduException, IOException, InvalidPinException {
    Logger.debug(logger, "Resetting User PIN");
    byte p1 = 2;
    Kdf kdf = getKdf();
    byte[] data = kdf.process(Pw.USER, newPin);
    if (resetCode != null) {
      Logger.debug(logger, "Using Reset Code");
      byte[] resetCodeBytes = kdf.process(Pw.RESET, resetCode);
      data =
          ByteBuffer.allocate(resetCodeBytes.length + data.length)
              .put(resetCodeBytes)
              .put(data)
              .array();
      p1 = 0;
    }

    try {
      protocol.sendAndReceive(new Apdu(0, INS_RESET_RETRY_COUNTER, p1, Pw.USER.getValue(), data));
    } catch (ApduException e) {
      if (e.getSw() == SW.SECURITY_CONDITION_NOT_SATISFIED && resetCode != null) {
        int resetRemaining = getPinStatus().getAttemptsReset();
        throw new InvalidPinException(
            resetRemaining, "Invalid Reset Code, " + resetRemaining + " tries remaining");
      }
      throw e;
    }
    Logger.info(logger, "New User PIN has been set");
  }

  /**
   * Get the User Interaction Flag (touch requirement) for a key.
   *
   * @param keyRef the key slot to read UIF for
   * @return the User Interaction Flag for the given slot
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public Uif getUif(KeyRef keyRef) throws ApduException, IOException {
    try {
      return Uif.fromValue(getData(keyRef.getUif())[0]);
    } catch (ApduException e) {
      if (e.getSw() == SW.WRONG_PARAMETERS_P1P2) {
        // Not supported
        return Uif.OFF;
      }
      throw e;
    }
  }

  /**
   * Set the User Interaction Flag (touch requirement) for a key.
   *
   * <p>Requires Admin PIN verification.
   *
   * @param keyRef the key slot to set UIF for
   * @param uif the UIF setting to use for the key in the given slot
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void setUif(KeyRef keyRef, Uif uif) throws ApduException, IOException {
    require(FEATURE_UIF);

    if (keyRef == KeyRef.ATT) {
      require(FEATURE_ATTESTATION);
    }
    if (uif.isCached()) {
      require(FEATURE_CACHED);
    }

    Logger.debug(logger, "Setting UIF for {} to {}", keyRef, uif);

    if (getUif(keyRef).isFixed()) {
      throw new IllegalStateException("Cannot change UIF when set to FIXED");
    }

    putData(keyRef.getUif(), uif.getBytes());
    Logger.info(logger, "UIF changed for {}", keyRef);
  }

  /**
   * Get the supported key algorithms for each of the key slots.
   *
   * @return a mapping from key ref to list of supported algorithms
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   * @throws BadResponseException in case of incorrect YubiKey response
   */
  public Map<KeyRef, List<AlgorithmAttributes>> getAlgorithmInformation()
      throws ApduException, IOException, BadResponseException {
    if (!getExtendedCapabilities()
        .getFlags()
        .contains(ExtendedCapabilityFlag.ALGORITHM_ATTRIBUTES_CHANGEABLE)) {
      throw new UnsupportedOperationException("Writing Algorithm Attributes is not supported");
    }

    Map<KeyRef, List<AlgorithmAttributes>> data = new HashMap<>();
    if (version.isLessThan(5, 2, 0)) {
      AlgorithmAttributes.Rsa.ImportFormat fmt;
      List<Integer> sizes = new ArrayList<>();
      sizes.add(2048);
      if (version.isLessThan(4, 0, 0)) {
        // Needed by Neo
        fmt = AlgorithmAttributes.Rsa.ImportFormat.CRT_W_MOD;
      } else {
        fmt = AlgorithmAttributes.Rsa.ImportFormat.STANDARD;
        if (!(version.major == 4 && version.minor == 4)) {
          // Non-FIPS
          sizes.add(3072);
          sizes.add(4096);
        }
      }
      List<AlgorithmAttributes> attributes = new ArrayList<>();
      for (int size : sizes) {
        attributes.add(AlgorithmAttributes.Rsa.create(size, fmt));
      }
      data.put(KeyRef.SIG, Collections.unmodifiableList(attributes));
      data.put(KeyRef.DEC, Collections.unmodifiableList(attributes));
      data.put(KeyRef.AUT, Collections.unmodifiableList(attributes));
    } else {
      Logger.debug(logger, "Getting supported Algorithm Information");
      byte[] buf = getData(Do.ALGORITHM_INFORMATION);
      try {
        buf = Tlvs.unpackValue(Do.ALGORITHM_INFORMATION, buf);
      } catch (BufferUnderflowException e) {
        buf = Arrays.copyOf(buf, buf.length + 2);
        buf = Tlvs.unpackValue(Do.ALGORITHM_INFORMATION, buf);
        buf = Arrays.copyOf(buf, buf.length - 2);
      }
      Map<Integer, KeyRef> refs = new HashMap<>();
      for (KeyRef ref : KeyRef.values()) {
        refs.put(ref.getAlgorithmAttributes(), ref);
      }
      for (Tlv tlv : Tlvs.decodeList(buf)) {
        KeyRef ref = refs.get(tlv.getTag());
        if (!data.containsKey(ref)) {
          data.put(ref, new ArrayList<>());
        }
        data.get(ref).add(AlgorithmAttributes.parse(tlv.getValue()));
      }

      if (version.isLessThan(5, 6, 1)) {
        // Fix for invalid Curve25519 entries:
        // Remove X25519 with EdDSA from all keys
        AlgorithmAttributes invalidX25519 =
            new AlgorithmAttributes.Ec(
                (byte) 0x16, OpenPgpCurve.X25519, AlgorithmAttributes.Ec.ImportFormat.STANDARD);
        for (List<AlgorithmAttributes> values : data.values()) {
          values.remove(invalidX25519);
        }

        AlgorithmAttributes x25519 =
            new AlgorithmAttributes.Ec(
                (byte) 0x12, OpenPgpCurve.X25519, AlgorithmAttributes.Ec.ImportFormat.STANDARD);

        // Add X25519 ECDH for DEC
        if (!data.get(KeyRef.DEC).contains(x25519)) {
          data.get(KeyRef.DEC).add(x25519);
        }

        // Remove EdDSA from DEC, ATT
        AlgorithmAttributes ed25519 =
            new AlgorithmAttributes.Ec(
                (byte) 0x16, OpenPgpCurve.Ed25519, AlgorithmAttributes.Ec.ImportFormat.STANDARD);
        data.get(KeyRef.DEC).remove(ed25519);
        data.get(KeyRef.ATT).remove(ed25519);
      }
    }

    return data;
  }

  /**
   * Sets the algorithm attributes to use for a key slot.
   *
   * @param keyRef the key slot to set attributes for
   * @param attributes the algorithm attributes to set for the slot
   * @throws BadResponseException in case of incorrect YubiKey response
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void setAlgorithmAttributes(KeyRef keyRef, AlgorithmAttributes attributes)
      throws BadResponseException, ApduException, IOException {
    Logger.debug(logger, "Setting Algorithm Attributes for {}", keyRef);

    Map<KeyRef, List<AlgorithmAttributes>> supported = getAlgorithmInformation();
    if (!supported.containsKey(keyRef)) {
      throw new UnsupportedOperationException("Key slot not supported");
    }
    List<AlgorithmAttributes> supportedAttributes = supported.get(keyRef);
    if (!supportedAttributes.contains(attributes)) {
      throw new UnsupportedOperationException("Algorithm attributes not supported: " + attributes);
    }

    putData(keyRef.getAlgorithmAttributes(), attributes.getBytes());
    Logger.info(logger, "Algorithm Attributes have been changed");
  }

  /**
   * Set the generation timestamp of a key.
   *
   * @param keyRef the key slot to set the timestamp for
   * @param timestamp the timestamp to set
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void setGenerationTime(KeyRef keyRef, int timestamp) throws ApduException, IOException {
    Logger.debug(logger, "Setting key generation timestamp for {}", keyRef);
    putData(keyRef.getGenerationTime(), ByteBuffer.allocate(4).putInt(timestamp).array());
    Logger.info(logger, "Key generation timestamp set for {}", keyRef);
  }

  /**
   * Set the fingerprint of a key, format specified in RFC 4880.
   *
   * @param keyRef the slot of the key to set the fingerprint for
   * @param fingerprint the fingerprint to set
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void setFingerprint(KeyRef keyRef, byte[] fingerprint) throws ApduException, IOException {
    Logger.debug(logger, "Setting key fingerprint for {}", keyRef);
    putData(keyRef.getFingerprint(), fingerprint);
    Logger.info(logger, "Key fingerprint set for {}", keyRef);
  }

  private void selectCertificate(KeyRef keyRef) throws ApduException, IOException {
    if (version.isAtLeast(5, 2, 0)) {
      require(FEATURE_ATTESTATION);
      byte[] data =
          new Tlv(
                  0x60,
                  new Tlv(
                          0x5c,
                          new byte[] {
                            Do.CARDHOLDER_CERTIFICATE >> 8, Do.CARDHOLDER_CERTIFICATE & 0xff
                          })
                      .getBytes())
              .getBytes();
      if (version.isLessThan(5, 4, 4)) {
        // These use a non-standard byte in the command, prepend the length
        data = ByteBuffer.allocate(1 + data.length).put((byte) data.length).put(data).array();
      }
      protocol.sendAndReceive(new Apdu(0, INS_SELECT_DATA, 3 - keyRef.getValue(), 0x04, data));
    } else if (keyRef != KeyRef.AUT) {
      // AUT is the default slot, any other slot fails
      throw new UnsupportedOperationException("Selecting certificate not supported");
    }
  }

  /**
   * Get a certificate from a slot.
   *
   * @param keyRef the slot to get a certificate from
   * @return the certificate stored in the give slot
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  @Nullable
  public X509Certificate getCertificate(KeyRef keyRef) throws ApduException, IOException {
    Logger.debug(logger, "Getting certificate for key {}", keyRef);
    byte[] data;
    if (keyRef == KeyRef.ATT) {
      require(FEATURE_ATTESTATION);
      data = getData(Do.ATT_CERTIFICATE);
    } else {
      selectCertificate(keyRef);
      data = getData(Do.CARDHOLDER_CERTIFICATE);
    }
    if (data.length == 0) {
      return null;
    }
    try (InputStream stream = new ByteArrayInputStream(data)) {
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      return (X509Certificate) cf.generateCertificate(stream);
    } catch (CertificateException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Imports a certificate into a slot.
   *
   * <p>Requires Admin PIN verification.
   *
   * @param keyRef the slot to put the certificate in
   * @param certificate the certificate to import
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void putCertificate(KeyRef keyRef, X509Certificate certificate)
      throws ApduException, IOException {
    byte[] certData;
    try {
      certData = certificate.getEncoded();
    } catch (CertificateEncodingException e) {
      throw new IllegalArgumentException("Failed to get encoded version of certificate", e);
    }
    Logger.debug(logger, "Importing certificate for key {}", keyRef);
    if (keyRef == KeyRef.ATT) {
      require(FEATURE_ATTESTATION);
      putData(Do.ATT_CERTIFICATE, certData);
    } else {
      selectCertificate(keyRef);
      putData(Do.CARDHOLDER_CERTIFICATE, certData);
    }
    Logger.info(logger, "Certificate imported for key {}", keyRef);
  }

  /**
   * Deletes a certificate in a slot.
   *
   * <p>Requires Admin PIN verification.
   *
   * @param keyRef the slot in which to delete the certificate
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void deleteCertificate(KeyRef keyRef) throws ApduException, IOException {
    Logger.debug(logger, "Deleting certificate for key {}", keyRef);
    if (keyRef == KeyRef.ATT) {
      require(FEATURE_ATTESTATION);
      putData(Do.ATT_CERTIFICATE, new byte[0]);
    } else {
      selectCertificate(keyRef);
      putData(Do.CARDHOLDER_CERTIFICATE, new byte[0]);
    }
    Logger.info(logger, "Certificate deleted for key {}", keyRef);
  }

  static AlgorithmAttributes getKeyAttributes(
      PrivateKeyValues values, KeyRef keyRef, Version version) {
    if (values instanceof PrivateKeyValues.Rsa) {
      return AlgorithmAttributes.Rsa.create(
          values.getBitLength(),
          version.isLessThan(4, 0, 0)
              ? AlgorithmAttributes.Rsa.ImportFormat.CRT_W_MOD
              : AlgorithmAttributes.Rsa.ImportFormat.STANDARD);
    } else if (values instanceof PrivateKeyValues.Ec) {
      return AlgorithmAttributes.Ec.create(
          keyRef, OpenPgpCurve.valueOf(((PrivateKeyValues.Ec) values).getCurveParams().name()));
    } else {
      throw new IllegalArgumentException("Unsupported private key type");
    }
  }

  static PrivateKeyTemplate getKeyTemplate(PrivateKeyValues values, KeyRef keyRef, boolean useCrt) {
    if (values instanceof PrivateKeyValues.Rsa) {
      int byteLength = values.getBitLength() / 8 / 2;
      PrivateKeyValues.Rsa rsaValues = (PrivateKeyValues.Rsa) values;
      if (useCrt) {
        return new PrivateKeyTemplate.RsaCrt(
            keyRef.getCrt(),
            rsaValues.getPublicExponent().toByteArray(),
            intToLength(rsaValues.getPrimeP(), byteLength),
            intToLength(rsaValues.getPrimeQ(), byteLength),
            intToLength(Objects.requireNonNull(rsaValues.getCrtCoefficient()), byteLength),
            intToLength(Objects.requireNonNull(rsaValues.getPrimeExponentP()), byteLength),
            intToLength(Objects.requireNonNull(rsaValues.getPrimeExponentQ()), byteLength),
            intToLength(rsaValues.getModulus(), byteLength * 2));
      } else {
        return new PrivateKeyTemplate.Rsa(
            keyRef.getCrt(),
            rsaValues.getPublicExponent().toByteArray(),
            intToLength(rsaValues.getPrimeP(), byteLength),
            intToLength(rsaValues.getPrimeQ(), byteLength));
      }
    } else if (values instanceof PrivateKeyValues.Ec) {
      return new PrivateKeyTemplate.Ec(
          keyRef.getCrt(), ((PrivateKeyValues.Ec) values).getSecret(), null);
    }
    throw new UnsupportedOperationException("Unsupported private key type");
  }

  /**
   * Generate an RSA key in the given slot.
   *
   * <p>Requires Admin PIN verification.
   *
   * @param keyRef the slot to generate the key in
   * @param keySize the bitlength of the key to generate
   * @return the public key of the generated key pair
   * @throws BadResponseException in case of incorrect YubiKey response
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public PublicKeyValues generateRsaKey(KeyRef keyRef, int keySize)
      throws BadResponseException, ApduException, IOException {
    require(FEATURE_RSA_GENERATION);
    Logger.debug(logger, "Generating RSA private key for {}", keyRef);

    if (getExtendedCapabilities()
        .getFlags()
        .contains(ExtendedCapabilityFlag.ALGORITHM_ATTRIBUTES_CHANGEABLE)) {
      setAlgorithmAttributes(
          keyRef,
          AlgorithmAttributes.Rsa.create(keySize, AlgorithmAttributes.Rsa.ImportFormat.STANDARD));
    } else if (keySize != 2048) {
      throw new UnsupportedOperationException("Algorithm attributes not supported");
    }

    byte[] resp =
        protocol.sendAndReceive(new Apdu(0, INS_GENERATE_ASYM, 0x80, 0x00, keyRef.getCrt()));
    if (version.isLessThan(5, 0, 0)) {
      setGenerationTime(keyRef, 0);
    }
    Map<Integer, byte[]> data = Tlvs.decodeMap(Tlvs.unpackValue(TAG_PUBLIC_KEY, resp));
    Logger.info(logger, "RSA key generated for {}", keyRef);
    return new PublicKeyValues.Rsa(
        new BigInteger(1, data.get(0x81)), new BigInteger(1, data.get(0x82)));
  }

  /**
   * Generate an EC key in the given slot.
   *
   * <p>Requires Admin PIN verification.
   *
   * @param keyRef the key slot to generate a key in
   * @param curve the elliptic curve of the key to generate
   * @return the public key of the generated key pair
   * @throws BadResponseException in case of incorrect YubiKey response
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public PublicKeyValues generateEcKey(KeyRef keyRef, OpenPgpCurve curve)
      throws BadResponseException, ApduException, IOException {
    require(FEATURE_EC_KEYS);
    Logger.debug(logger, "Generating EC private key for {}", keyRef);

    setAlgorithmAttributes(keyRef, AlgorithmAttributes.Ec.create(keyRef, curve));

    byte[] resp =
        protocol.sendAndReceive(new Apdu(0, INS_GENERATE_ASYM, 0x80, 0x00, keyRef.getCrt()));
    if (version.isLessThan(5, 0, 0)) {
      setGenerationTime(keyRef, 0);
    }
    Map<Integer, byte[]> data = Tlvs.decodeMap(Tlvs.unpackValue(TAG_PUBLIC_KEY, resp));
    Logger.info(logger, "EC key generated for {}", keyRef);
    byte[] encoded = data.get(0x86);
    if (curve == OpenPgpCurve.Ed25519 || curve == OpenPgpCurve.X25519) {
      return new PublicKeyValues.Cv25519(curve.getValues(), encoded);
    }
    return PublicKeyValues.Ec.fromEncodedPoint(curve.getValues(), encoded);
  }

  /**
   * Import a private key into the give slot.
   *
   * <p>Requires Admin PIN verification.
   *
   * @param keyRef the slot to import the key into
   * @param privateKey the private key to import
   * @throws BadResponseException in case of incorrect YubiKey response
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void putKey(KeyRef keyRef, PrivateKeyValues privateKey)
      throws BadResponseException, ApduException, IOException {
    Logger.debug(logger, "Importing a private key for {}", keyRef);
    AlgorithmAttributes attributes = getKeyAttributes(privateKey, keyRef, version);

    if (getExtendedCapabilities()
        .getFlags()
        .contains(ExtendedCapabilityFlag.ALGORITHM_ATTRIBUTES_CHANGEABLE)) {
      setAlgorithmAttributes(keyRef, attributes);
    } else {
      if (!(attributes instanceof AlgorithmAttributes.Rsa
          && ((AlgorithmAttributes.Rsa) attributes).getNLen() == 2048)) {
        throw new UnsupportedOperationException("This YubiKey only supports RSA 2048 keys");
      }
    }
    PrivateKeyTemplate template = null;
    byte[] templateBytes = null;
    try {
      template = getKeyTemplate(privateKey, keyRef, version.isLessThan(4, 0, 0));
      templateBytes = template.getBytes();
      protocol.sendAndReceive(new Apdu(0, INS_PUT_DATA_ODD, 0x3f, 0xff, templateBytes));
    } finally {
      if (templateBytes != null) {
        Arrays.fill(templateBytes, (byte) 0);
      }
      if (template != null) {
        template.destroy();
      }
    }

    if (version.isLessThan(5, 0, 0)) {
      setGenerationTime(keyRef, 0);
    }
    Logger.info(logger, "Private key imported for {}", keyRef);
  }

  /**
   * Read the public key from a slot.
   *
   * @param keyRef the key slot to read from
   * @return the public key stored in the given slot
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   * @throws BadResponseException in case of incorrect YubiKey response
   */
  public PublicKeyValues getPublicKey(KeyRef keyRef)
      throws ApduException, IOException, BadResponseException {
    Logger.debug(logger, "Getting public key for {}", keyRef);
    byte[] resp =
        protocol.sendAndReceive(new Apdu(0, INS_GENERATE_ASYM, 0x81, 0x00, keyRef.getCrt()));
    Map<Integer, byte[]> data = Tlvs.decodeMap(Tlvs.unpackValue(TAG_PUBLIC_KEY, resp));
    AlgorithmAttributes attributes =
        getApplicationRelatedData().getDiscretionary().getAlgorithmAttributes(keyRef);
    if (attributes instanceof AlgorithmAttributes.Ec) {
      byte[] encoded = data.get(0x86);
      OpenPgpCurve curve = ((AlgorithmAttributes.Ec) attributes).getCurve();
      if (curve == OpenPgpCurve.Ed25519 || curve == OpenPgpCurve.X25519) {
        return new PublicKeyValues.Cv25519(curve.getValues(), encoded);
      }
      return PublicKeyValues.Ec.fromEncodedPoint(curve.getValues(), encoded);
    } else {
      return new PublicKeyValues.Rsa(
          new BigInteger(1, data.get(0x81)), new BigInteger(1, data.get(0x82)));
    }
  }

  /**
   * Deletes the key in a key slot.
   *
   * @param keyRef the slot to delete
   * @throws BadResponseException in case of incorrect YubiKey response
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public void deleteKey(KeyRef keyRef) throws BadResponseException, ApduException, IOException {
    Logger.debug(logger, "Deleting private key for {}", keyRef);
    if (version.isLessThan(4, 0, 0)) {
      Logger.debug(logger, "Overwriting with dummy key");
      // Import over the key, using a dummy
      try {
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        putKey(keyRef, PrivateKeyValues.fromPrivateKey(rsaGen.generateKeyPair().getPrivate()));
      } catch (NoSuchAlgorithmException e) {
        throw new RuntimeException(e);
      }
    } else {
      Logger.debug(logger, "Changing algorithm attributes");
      // Delete key by changing the key attributes twice.
      // Use putData to avoid checking for RSA 4096 support
      putData(
          keyRef.getAlgorithmAttributes(),
          AlgorithmAttributes.Rsa.create(4096, AlgorithmAttributes.Rsa.ImportFormat.STANDARD)
              .getBytes());
      setAlgorithmAttributes(
          keyRef,
          AlgorithmAttributes.Rsa.create(2048, AlgorithmAttributes.Rsa.ImportFormat.STANDARD));
    }
    Logger.info(logger, "Private key deleted for {}", keyRef);
  }

  static byte[] formatDssSignature(byte[] response) {
    int split = response.length / 2;
    BigInteger r = new BigInteger(1, Arrays.copyOfRange(response, 0, split));
    BigInteger s = new BigInteger(1, Arrays.copyOfRange(response, split, response.length));
    return new Tlv(
            0x30,
            Tlvs.encodeList(
                Arrays.asList(new Tlv(0x02, r.toByteArray()), new Tlv(0x02, s.toByteArray()))))
        .getBytes();
  }

  /**
   * Signs a message using the SIG key.
   *
   * <p>NOTE: This performs a raw signature. Messages should be hashed and/or padded prior. Requires
   * User PIN verification.
   *
   * @param payload the message to sign
   * @return the generated signature
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public byte[] sign(byte[] payload) throws ApduException, IOException {
    AlgorithmAttributes attributes =
        Objects.requireNonNull(
            getApplicationRelatedData().getDiscretionary().getAlgorithmAttributes(KeyRef.SIG));
    Logger.debug(logger, "Signing a message with {}", attributes);
    byte[] response = protocol.sendAndReceive(new Apdu(0, INS_PSO, 0x9e, 0x9a, payload));
    Logger.info(logger, "Message signed");
    if (attributes.getAlgorithmId() == 0x13) {
      return formatDssSignature(response);
    }
    return response;
  }

  /**
   * Decrypts a value using the DEC key.
   *
   * <p>This method should be used for RSA keys to perform an RSA decryption using PKCS#1 v1.5
   * padding. For RSA the `value` should be an encrypted block. For ECDH the `value` should be a
   * peer public-key to perform the key exchange with, and the result will be the derived shared
   * secret.
   *
   * <p>Requires (extended) User PIN verification.
   *
   * @param payload the ciphertext to decrypt
   * @return the decrypted and unpadded plaintext
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public byte[] decrypt(byte[] payload) throws ApduException, IOException {
    Logger.debug(logger, "Decrypting a value");
    byte[] response =
        protocol.sendAndReceive(
            new Apdu(
                0,
                INS_PSO,
                0x80,
                0x86,
                ByteBuffer.allocate(payload.length + 1).put((byte) 0).put(payload).array()));
    Logger.info(logger, "Value decrypted");
    return response;
  }

  /**
   * Performs an ECDH key agreement using the DEC key.
   *
   * <p>This method should be used for EC keys where encryption is done using a shared secret.
   *
   * @param peerPublicKey the public key to perform the agreement with
   * @return the key agreement shared secret
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public byte[] decrypt(PublicKeyValues peerPublicKey) throws ApduException, IOException {
    byte[] encodedPoint;
    if (peerPublicKey instanceof PublicKeyValues.Ec) {
      encodedPoint = ((PublicKeyValues.Ec) peerPublicKey).getEncodedPoint();
    } else if (peerPublicKey instanceof PublicKeyValues.Cv25519) {
      encodedPoint = ((PublicKeyValues.Cv25519) peerPublicKey).getBytes();
    } else {
      throw new IllegalArgumentException("peerPublicKey must be an Elliptic Curve key");
    }

    byte[] response =
        protocol.sendAndReceive(
            new Apdu(
                0,
                INS_PSO,
                0x80,
                0x86,
                new Tlv(0xA6, new Tlv(0x7F49, new Tlv(0x86, encodedPoint).getBytes()).getBytes())
                    .getBytes()));
    Logger.info(logger, "ECDH key agreement performed");
    return response;
  }

  /**
   * Authenticates a message using the AUT key.
   *
   * <p>Requires User PIN verification.
   *
   * @param payload the message to authenticate
   * @return the generated signature
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public byte[] authenticate(byte[] payload) throws ApduException, IOException {
    AlgorithmAttributes attributes =
        Objects.requireNonNull(
            getApplicationRelatedData().getDiscretionary().getAlgorithmAttributes(KeyRef.AUT));
    Logger.debug(logger, "Authenticating a message with {}", attributes);
    byte[] response =
        protocol.sendAndReceive(new Apdu(0, INS_INTERNAL_AUTHENTICATE, 0x0, 0x0, payload));
    Logger.info(logger, "Message authenticated");
    if (attributes.getAlgorithmId() == 0x13) {
      return formatDssSignature(response);
    }
    return response;
  }

  /**
   * Creates an attestation certificate for a key.
   *
   * <p>The certificate is written to the certificate slot for the key, and its content is returned.
   *
   * <p>Requires User PIN verification.
   *
   * @param keyRef the slot to attest
   * @return the attestation certificate
   * @throws ApduException in case of an error response from the YubiKey
   * @throws IOException in case of connection error
   */
  public X509Certificate attestKey(KeyRef keyRef) throws ApduException, IOException {
    require(FEATURE_ATTESTATION);

    Logger.debug(logger, "Attesting key {}", keyRef);
    protocol.sendAndReceive(new Apdu(0x80, INS_GET_ATTESTATION, keyRef.getValue(), 0, null));
    Logger.info(logger, "Attestation certificate created for {}", keyRef);

    return Objects.requireNonNull(getCertificate(keyRef));
  }
}

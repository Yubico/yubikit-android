/*
 * Copyright (C) 2019-2025 Yubico.
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

package com.yubico.yubikit.piv;

import static com.yubico.yubikit.core.application.SessionVersionOverride.overrideOf;
import static com.yubico.yubikit.core.util.ByteUtils.intToLength;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.ApplicationSession;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.application.Feature;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.keys.EllipticCurveValues;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.slf4j.LoggerFactory;

/**
 * Personal Identity Verification (PIV) interface specified in NIST SP 800-73 document
 * "Cryptographic Algorithms and Key Sizes for PIV".
 *
 * <p>This enables you to perform RSA or ECC sign/decrypt operations using a private key stored on
 * the smart card, through common transports like PKCS#11.
 */
public class PivSession extends ApplicationSession<PivSession> {
  // Features
  /** Support for the NIST P-348 elliptic curve. */
  public static final Feature<PivSession> FEATURE_P384 =
      new Feature.Versioned<>("Curve P384", 4, 0, 0);

  /** Support for custom PIN or Touch policy. */
  public static final Feature<PivSession> FEATURE_USAGE_POLICY =
      new Feature.Versioned<>("PIN/Touch Policy", 4, 0, 0);

  /** Support for the CACHED Touch policy. */
  public static final Feature<PivSession> FEATURE_TOUCH_CACHED =
      new Feature.Versioned<>("Cached Touch Policy", 4, 3, 0);

  /** Support for Attestation of generated keys. */
  public static final Feature<PivSession> FEATURE_ATTESTATION =
      new Feature.Versioned<>("Attestation", 4, 3, 0);

  /** Support for reading the YubiKey serial number. */
  public static final Feature<PivSession> FEATURE_SERIAL =
      new Feature.Versioned<>("Serial Number", 5, 0, 0);

  /** Support for getting PIN/PUK/Management key and private key metadata. */
  public static final Feature<PivSession> FEATURE_METADATA =
      new Feature.Versioned<>("Metadata", 5, 3, 0);

  /** Support for AES management keys. */
  public static final Feature<PivSession> FEATURE_AES_KEY =
      new Feature.Versioned<>("AES Management Key", 5, 4, 0);

  /** Support for generating RSA keys. */
  public static final Feature<PivSession> FEATURE_RSA_GENERATION =
      new Feature<PivSession>("RSA key generation") {
        @Override
        public boolean isSupportedBy(Version version) {
          return version.isLessThan(4, 2, 6) || version.isAtLeast(4, 3, 5);
        }
      };

  /** Support for moving and deleting keys. */
  public static final Feature<PivSession> FEATURE_MOVE_KEY =
      new Feature.Versioned<>("Move or delete keys", 5, 7, 0);

  /** Support for the curve 25519 keys. */
  public static final Feature<PivSession> FEATURE_CV25519 =
      new Feature.Versioned<>("Curve 25519", 5, 7, 0);

  /** Support for larger RSA key sizes. */
  public static final Feature<PivSession> FEATURE_RSA3072_RSA4096 =
      new Feature.Versioned<>("RSA3072 and RSA4096 keys", 5, 7, 0);

  private static final int PIN_LEN = 8;
  private static final int TEMPORARY_PIN_LEN = 16;

  // Special slot for the Management Key
  private static final int SLOT_CARD_MANAGEMENT = 0x9b;

  // Special slot for bio metadata
  private static final int SLOT_OCC_AUTH = 0x96;

  // Instruction set
  private static final byte INS_VERIFY = 0x20;
  private static final byte INS_CHANGE_REFERENCE = 0x24;
  private static final byte INS_RESET_RETRY = 0x2c;
  private static final byte INS_GENERATE_ASYMMETRIC = 0x47;
  private static final byte INS_AUTHENTICATE = (byte) 0x87;
  private static final byte INS_GET_DATA = (byte) 0xcb;
  private static final byte INS_PUT_DATA = (byte) 0xdb;
  private static final byte INS_MOVE_KEY = (byte) 0xf6;
  private static final byte INS_GET_METADATA = (byte) 0xf7;
  private static final byte INS_GET_SERIAL = (byte) 0xf8;
  private static final byte INS_ATTEST = (byte) 0xf9;
  private static final byte INS_SET_PIN_RETRIES = (byte) 0xfa;
  private static final byte INS_RESET = (byte) 0xfb;
  private static final byte INS_GET_VERSION = (byte) 0xfd;
  private static final byte INS_IMPORT_KEY = (byte) 0xfe;
  private static final byte INS_SET_MGMKEY = (byte) 0xff;

  // Tags for parsing responses and preparing requests
  private static final int TAG_AUTH_WITNESS = 0x80;
  private static final int TAG_AUTH_CHALLENGE = 0x81;
  private static final int TAG_AUTH_RESPONSE = 0x82;
  private static final int TAG_AUTH_EXPONENTIATION = 0x85;
  private static final int TAG_GEN_ALGORITHM = 0x80;
  private static final int TAG_OBJ_DATA = 0x53;
  private static final int TAG_OBJ_ID = 0x5c;
  private static final int TAG_CERTIFICATE = 0x70;
  private static final int TAG_CERT_INFO = 0x71;
  private static final int TAG_DYN_AUTH = 0x7c;
  private static final int TAG_LRC = 0xfe;
  private static final int TAG_PIN_POLICY = 0xaa;
  private static final int TAG_TOUCH_POLICY = 0xab;

  // Metadata tags
  private static final int TAG_METADATA_ALGO = 0x01;
  private static final int TAG_METADATA_POLICY = 0x02;
  private static final int TAG_METADATA_ORIGIN = 0x03;
  private static final int TAG_METADATA_PUBLIC_KEY = 0x04;
  private static final int TAG_METADATA_IS_DEFAULT = 0x05;
  private static final int TAG_METADATA_RETRIES = 0x06;
  private static final int TAG_METADATA_BIO_CONFIGURED = 0x07;
  private static final int TAG_METADATA_TEMPORARY_PIN = 0x08;

  private static final byte ORIGIN_GENERATED = 1;
  private static final byte ORIGIN_IMPORTED = 2;

  private static final int INDEX_PIN_POLICY = 0;
  private static final int INDEX_TOUCH_POLICY = 1;
  private static final int INDEX_RETRIES_TOTAL = 0;
  private static final int INDEX_RETRIES_REMAINING = 1;

  private static final byte PIN_P2 = (byte) 0x80;
  private static final byte PUK_P2 = (byte) 0x81;

  private final SmartCardProtocol protocol;
  private final Version version;
  private int currentPinAttempts = 3; // Internal guess as to number of PIN retries.
  private int maxPinAttempts = 3; // Internal guess as to max number of PIN retries.
  private ManagementKeyType managementKeyType;

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(PivSession.class);

  /**
   * Create new instance of {@link PivSession} and selects the application for use
   *
   * @param connection connection with YubiKey
   * @throws IOException in case of communication error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws ApplicationNotAvailableException if the application is missing or disabled
   */
  public PivSession(SmartCardConnection connection)
      throws IOException, ApduException, ApplicationNotAvailableException {
    this(connection, null);
  }

  /**
   * Create new instance of {@link PivSession} and selects the application for use
   *
   * @param connection connection with YubiKey
   * @throws IOException in case of communication error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws ApplicationNotAvailableException if the application is missing or disabled
   */
  public PivSession(SmartCardConnection connection, @Nullable ScpKeyParams scpKeyParams)
      throws IOException, ApduException, ApplicationNotAvailableException {
    protocol = new SmartCardProtocol(connection);
    protocol.select(AppId.PIV);
    if (scpKeyParams != null) {
      try {
        protocol.initScp(scpKeyParams);
      } catch (BadResponseException e) {
        throw new IllegalStateException(e);
      }
    }

    version =
        overrideOf(
            Version.fromBytes(protocol.sendAndReceive(new Apdu(0, INS_GET_VERSION, 0, 0, null))));
    protocol.configure(version);

    try {
      managementKeyType = getManagementKeyMetadata().getKeyType();
    } catch (UnsupportedOperationException unsupportedOperationException) {
      managementKeyType = ManagementKeyType.TDES;
    }
    Logger.debug(logger, "PIV session initialized (version={})", version);
  }

  @Override
  public void close() throws IOException {
    protocol.close();
  }

  /**
   * Get the PIV application version from the YubiKey. For YubiKey 4 and later this will match the
   * YubiKey firmware version.
   *
   * @return application version
   */
  @Override
  public Version getVersion() {
    return version;
  }

  /**
   * Get the serial number from the YubiKey. NOTE: This requires the SERIAL_API_VISIBLE flag to be
   * set on one of the YubiOTP slots (it is set by default).
   *
   * <p>This functionality requires support for {@link #FEATURE_SERIAL}, available on YubiKey 5 or
   * later.
   *
   * @return The YubiKey's serial number
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public int getSerialNumber() throws IOException, ApduException {
    require(FEATURE_SERIAL);
    return ByteBuffer.wrap(protocol.sendAndReceive(new Apdu(0, INS_GET_SERIAL, 0, 0, null)))
        .getInt();
  }

  /**
   * Resets the application to just-installed state.
   *
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public void reset() throws IOException, ApduException {
    Logger.debug(logger, "Preparing PIV reset");

    try {
      BioMetadata bioMetadata = getBioMetadata();
      if (bioMetadata.isConfigured()) {
        throw new IllegalArgumentException(
            "Cannot perform PIV reset when biometrics are configured");
      }
    } catch (UnsupportedOperationException e) {
      // ignored
    }

    blockPin();
    blockPuk();
    Logger.debug(logger, "Sending reset");
    protocol.sendAndReceive(new Apdu(0, INS_RESET, 0, 0, null));
    currentPinAttempts = 3;
    maxPinAttempts = 3;

    // update management key type
    try {
      managementKeyType = getManagementKeyMetadata().getKeyType();
    } catch (UnsupportedOperationException unsupportedOperationException) {
      managementKeyType = ManagementKeyType.TDES;
    }

    Logger.info(logger, "PIV application data reset performed");
  }

  /**
   * Authenticate with the Management Key.
   *
   * @param keyType the algorithm used for the management key The default key uses TDES
   * @param managementKey management key as byte array The default 3DES/AES192 management key (9B)
   *     is 010203040506070801020304050607080102030405060708.
   * @throws IllegalArgumentException in case of wrong keyType
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   * @deprecated Replaced by {@link #authenticate(byte[])}
   */
  @Deprecated
  public void authenticate(ManagementKeyType keyType, byte[] managementKey)
      throws IOException, ApduException, BadResponseException {
    if (keyType != managementKeyType) {
      throw new IllegalArgumentException("Invalid Management Key type " + keyType.name());
    }
    authenticate(managementKey);
  }

  /**
   * Authenticate with the Management Key.
   *
   * @param managementKey management key as byte array The default 3DES/AES192 management key (9B)
   *     is 010203040506070801020304050607080102030405060708.
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   */
  public void authenticate(byte[] managementKey)
      throws IOException, ApduException, BadResponseException {
    Logger.debug(logger, "Authenticating with key type: {}", managementKeyType);
    if (managementKey.length != managementKeyType.keyLength) {
      throw new IllegalArgumentException(
          String.format("Management Key must be %d bytes", managementKeyType.keyLength));
    }
    // An empty witness is a request for a witness.
    byte[] request = new Tlv(TAG_DYN_AUTH, new Tlv(TAG_AUTH_WITNESS, null).getBytes()).getBytes();
    byte[] response =
        protocol.sendAndReceive(
            new Apdu(0, INS_AUTHENTICATE, managementKeyType.value, SLOT_CARD_MANAGEMENT, request));

    // Witness (tag '80') contains encrypted data (unrevealed fact).
    byte[] witness = Tlvs.unpackValue(TAG_AUTH_WITNESS, Tlvs.unpackValue(TAG_DYN_AUTH, response));
    SecretKey key = new SecretKeySpec(managementKey, managementKeyType.cipherName);
    try {
      Map<Integer, byte[]> dataTlvs = new LinkedHashMap<>();
      Cipher cipher = Cipher.getInstance(managementKeyType.cipherName + "/ECB/NoPadding");
      // This decrypted witness
      cipher.init(Cipher.DECRYPT_MODE, key);
      dataTlvs.put(TAG_AUTH_WITNESS, cipher.doFinal(witness));
      //  The challenge (tag '81') contains clear data (byte sequence),
      byte[] challenge = RandomUtils.getRandomBytes(managementKeyType.challengeLength);
      dataTlvs.put(TAG_AUTH_CHALLENGE, challenge);

      request = new Tlv(TAG_DYN_AUTH, Tlvs.encodeMap(dataTlvs)).getBytes();
      response =
          protocol.sendAndReceive(
              new Apdu(
                  0, INS_AUTHENTICATE, managementKeyType.value, SLOT_CARD_MANAGEMENT, request));

      // (tag '82') contains either the decrypted data from tag '80' or the encrypted data from tag
      // '81'.
      byte[] encryptedData =
          Tlvs.unpackValue(TAG_AUTH_RESPONSE, Tlvs.unpackValue(TAG_DYN_AUTH, response));
      cipher.init(Cipher.ENCRYPT_MODE, key);
      byte[] expectedData = cipher.doFinal(challenge);
      if (!MessageDigest.isEqual(encryptedData, expectedData)) {
        Logger.trace(
            logger,
            "Expected response: {} and actual response {}",
            StringUtils.bytesToHex(expectedData),
            StringUtils.bytesToHex(encryptedData));
        throw new BadResponseException("Calculated response for challenge is incorrect");
      }
    } catch (NoSuchAlgorithmException
        | InvalidKeyException
        | NoSuchPaddingException
        | BadPaddingException
        | IllegalBlockSizeException e) {
      // This should never happen
      throw new RuntimeException(e);
    }
  }

  /**
   * Create a signature for a given message.
   *
   * <p>The algorithm must be compatible with the given key type.
   *
   * <p>DEPRECATED: Use the PivProvider JCA Security Provider instead.
   *
   * @param slot the slot containing the private key to use
   * @param keyType the type of the key stored in the slot
   * @param message the message to hash
   * @param algorithm the signing algorithm to use
   * @return the signature
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   * @throws NoSuchAlgorithmException if the algorithm isn't supported
   */
  @Deprecated
  public byte[] sign(Slot slot, KeyType keyType, byte[] message, Signature algorithm)
      throws IOException, ApduException, BadResponseException, NoSuchAlgorithmException {
    Logger.debug(
        logger,
        "Signing data with key in slot {} of type {} using algorithm {}",
        slot,
        keyType,
        algorithm);
    byte[] payload = Padding.pad(keyType, message, algorithm);
    return usePrivateKey(slot, keyType, payload, false);
  }

  /**
   * Performs a private key operation on the given payload. Any hashing and/or padding required
   * should already be done prior to calling this method.
   *
   * <p>More commonly, the JCA classes provided should be used instead of directly calling this.
   *
   * @param slot the slot containing the private key to use
   * @param keyType the type of the key stored in the slot
   * @param payload the data to operate on
   * @return the result of the operation
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   */
  public byte[] rawSignOrDecrypt(Slot slot, KeyType keyType, byte[] payload)
      throws IOException, ApduException, BadResponseException {
    int byteLength = keyType.params.bitLength / 8;
    byte[] padded;
    if (keyType == KeyType.ED25519 || keyType == KeyType.X25519) {
      padded = payload;
    } else if (payload.length > byteLength) {
      if (keyType.params.algorithm == KeyType.Algorithm.EC) {
        // Truncate
        padded = Arrays.copyOf(payload, byteLength);
      } else {
        throw new IllegalArgumentException("Payload too large for key");
      }
    } else if (payload.length < byteLength) {
      // Left pad, with no external dependencies!
      padded = new byte[byteLength];
      System.arraycopy(payload, 0, padded, padded.length - payload.length, payload.length);
    } else {
      padded = payload;
    }
    Logger.debug(logger, "Decrypting data with key in slot {} of type {}", slot, keyType);
    return usePrivateKey(slot, keyType, padded, false);
  }

  /**
   * Decrypt an RSA-encrypted message.
   *
   * <p>DEPRECATED: Use the PivProvider JCA Security Provider instead.
   *
   * @param slot the slot containing the RSA private key to use
   * @param cipherText the encrypted payload to decrypt
   * @param algorithm the algorithm used for encryption
   * @return the decrypted plaintext
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   * @throws NoSuchPaddingException in case the padding algorithm isn't supported
   * @throws NoSuchAlgorithmException in case the algorithm isn't supported
   * @throws BadPaddingException in case of a padding error
   */
  @Deprecated
  public byte[] decrypt(Slot slot, byte[] cipherText, Cipher algorithm)
      throws IOException,
          ApduException,
          BadResponseException,
          NoSuchAlgorithmException,
          NoSuchPaddingException,
          BadPaddingException {
    KeyType keyType;
    switch (cipherText.length) {
      case 1024 / 8:
        keyType = KeyType.RSA1024;
        break;
      case 2048 / 8:
        keyType = KeyType.RSA2048;
        break;
      case 3072 / 8:
        keyType = KeyType.RSA3072;
        break;
      case 4096 / 8:
        keyType = KeyType.RSA4096;
        break;
      default:
        throw new IllegalArgumentException("Invalid length of ciphertext");
    }
    Logger.debug(logger, "Decrypting data with key in slot {} of type {}", slot, keyType);
    return Padding.unpad(usePrivateKey(slot, keyType, cipherText, false), algorithm);
  }

  /**
   * Perform an ECDH operation with a given public key to compute a shared secret.
   *
   * @param slot the slot containing the private EC key
   * @param peerPublicKey the peer public key for the operation
   * @return the shared secret, comprising the x-coordinate of the ECDH result point.
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   */
  @Deprecated
  public byte[] calculateSecret(Slot slot, ECPublicKey peerPublicKey)
      throws IOException, ApduException, BadResponseException {
    return calculateSecret(slot, peerPublicKey.getW());
  }

  /**
   * Perform an ECDH operation with a given public key to compute a shared secret.
   *
   * @param slot the slot containing the private EC key
   * @param peerPublicKey the peer public key for the operation
   * @return the shared secret, comprising the x-coordinate of the ECDH result point.
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   */
  @Deprecated
  public byte[] calculateSecret(Slot slot, ECPoint peerPublicKey)
      throws IOException, ApduException, BadResponseException {
    KeyType keyType =
        peerPublicKey.getAffineX().bitLength() > 256 ? KeyType.ECCP384 : KeyType.ECCP256;
    byte[] encodedPoint =
        new PublicKeyValues.Ec(
                ((KeyType.EcKeyParams) keyType.params).getCurveParams(),
                peerPublicKey.getAffineX(),
                peerPublicKey.getAffineY())
            .getEncodedPoint();
    Logger.debug(logger, "Performing key agreement with key in slot {} of type {}", slot, keyType);
    return usePrivateKey(slot, keyType, encodedPoint, true);
  }

  /**
   * Perform an ECDH operation with a given public key to compute a shared secret.
   *
   * @param slot the slot containing the private EC key
   * @param peerPublicKeyValues the peer public key values for the operation
   * @return the shared secret, comprising the x-coordinate of the ECDH result point.
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   * @throws NoSuchAlgorithmException in case of unsupported PublicKey type
   */
  public byte[] calculateSecret(Slot slot, PublicKeyValues peerPublicKeyValues)
      throws IOException, ApduException, BadResponseException, NoSuchAlgorithmException {
    if (peerPublicKeyValues instanceof PublicKeyValues.Cv25519) {
      PublicKeyValues.Cv25519 publicKeyValues = (PublicKeyValues.Cv25519) peerPublicKeyValues;
      KeyType keyType;
      if (publicKeyValues.getCurveParams() == EllipticCurveValues.X25519) {
        keyType = KeyType.X25519;
      } else {
        throw new NoSuchAlgorithmException("Illegal public key");
      }
      Logger.debug(
          logger, "Performing key agreement with key in slot {} of type {}", slot, keyType);
      return usePrivateKey(slot, keyType, publicKeyValues.getBytes(), true);
    } else if (peerPublicKeyValues instanceof PublicKeyValues.Ec) {
      PublicKeyValues.Ec publicKeyValues = (PublicKeyValues.Ec) peerPublicKeyValues;
      EllipticCurveValues ellipticCurveValues = publicKeyValues.getCurveParams();
      KeyType keyType =
          ellipticCurveValues.getBitLength() > 256 ? KeyType.ECCP384 : KeyType.ECCP256;
      Logger.debug(
          logger, "Performing key agreement with key in slot {} of type {}", slot, keyType);
      return usePrivateKey(slot, keyType, publicKeyValues.getEncodedPoint(), true);
    } else {
      throw new NoSuchAlgorithmException("Illegal public key");
    }
  }

  private byte[] usePrivateKey(Slot slot, KeyType keyType, byte[] message, boolean exponentiation)
      throws IOException, ApduException, BadResponseException {
    // using generic authentication for sign requests
    Map<Integer, byte[]> dataTlvs = new LinkedHashMap<>();
    dataTlvs.put(TAG_AUTH_RESPONSE, null);
    dataTlvs.put(exponentiation ? TAG_AUTH_EXPONENTIATION : TAG_AUTH_CHALLENGE, message);
    byte[] request = new Tlv(TAG_DYN_AUTH, Tlvs.encodeMap(dataTlvs)).getBytes();

    try {
      byte[] response =
          protocol.sendAndReceive(
              new Apdu(0, INS_AUTHENTICATE, keyType.value, slot.value, request));
      return Tlvs.unpackValue(TAG_AUTH_RESPONSE, Tlvs.unpackValue(TAG_DYN_AUTH, response));
    } catch (ApduException e) {
      if (SW.INCORRECT_PARAMETERS == e.getSw()) {
        // TODO: Replace with new CommandException subclass, wrapping e.
        throw new ApduException(
            e.getData(),
            e.getSw(),
            String.format(
                Locale.ROOT,
                "Make sure that %s key is generated on slot %02X",
                keyType.name(),
                slot.value));
      }
      throw e;
    }
  }

  /**
   * Change management key This method requires authentication {@link #authenticate}.
   *
   * <p>Thi setting requireTouch=true requires support for {@link #FEATURE_USAGE_POLICY}, available
   * on YubiKey 4 or later.
   *
   * @param managementKey new value of management key
   * @param requireTouch true to require touch for authentication
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public void setManagementKey(
      ManagementKeyType keyType, byte[] managementKey, boolean requireTouch)
      throws IOException, ApduException {
    Logger.debug(logger, "Setting management key of type: {}", keyType);
    if (keyType != ManagementKeyType.TDES) {
      require(FEATURE_AES_KEY);
    }
    if (requireTouch) {
      require(FEATURE_USAGE_POLICY);
    }
    if (managementKey.length != keyType.keyLength) {
      throw new IllegalArgumentException(
          String.format("Management key must be %d bytes", keyType.keyLength));
    }

    ByteArrayOutputStream stream = new ByteArrayOutputStream();
    stream.write(keyType.value);
    stream.write(new Tlv(SLOT_CARD_MANAGEMENT, managementKey).getBytes());

    // NOTE: if p2=0xfe key requires touch
    // Require touch is only available on YubiKey 4 & 5.
    protocol.sendAndReceive(
        new Apdu(0, INS_SET_MGMKEY, 0xff, requireTouch ? 0xfe : 0xff, stream.toByteArray()));
    managementKeyType = keyType;
    Logger.info(logger, "Management key set");
  }

  /**
   * Authenticate with pin 0 - PIN authentication blocked. Note: that 15 is the highest value that
   * will be returned even if remaining tries is higher.
   *
   * @param pin string with pin (UTF-8) The default PIN code is 123456.
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws InvalidPinException in case if pin is invalid
   */
  public void verifyPin(char[] pin) throws IOException, ApduException, InvalidPinException {
    try {
      Logger.debug(logger, "Verifying PIN");
      protocol.sendAndReceive(new Apdu(0, INS_VERIFY, 0, PIN_P2, pinBytes(pin)));
      currentPinAttempts = maxPinAttempts;
    } catch (ApduException e) {
      int retries = getRetriesFromCode(e.getSw());
      if (retries >= 0) {
        currentPinAttempts = retries;
        throw new InvalidPinException(retries);
      } else {
        // status code returned error, not number of retries
        throw e;
      }
    }
  }

  /**
   * Reads metadata specific to YubiKey Bio multi-protocol.
   *
   * @return metadata about a slot
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws UnsupportedOperationException in case the metadata cannot be retrieved
   */
  public BioMetadata getBioMetadata() throws IOException, ApduException {
    Logger.debug(logger, "Getting bio metadata");
    try {
      Map<Integer, byte[]> data =
          Tlvs.decodeMap(
              protocol.sendAndReceive(new Apdu(0, INS_GET_METADATA, 0, SLOT_OCC_AUTH, null)));
      return new BioMetadata(
          data.get(TAG_METADATA_BIO_CONFIGURED)[0] == 1,
          data.get(TAG_METADATA_RETRIES)[0],
          data.get(TAG_METADATA_TEMPORARY_PIN)[0] == 1);
    } catch (ApduException apduException) {
      if (apduException.getSw() == SW.REFERENCED_DATA_NOT_FOUND) {
        throw new UnsupportedOperationException(
            "Biometric verification not supported by this YubiKey");
      }
      throw apduException;
    }
  }

  /**
   * Authenticate with YubiKey Bio multi-protocol capabilities.
   *
   * <p>Before calling this method, clients must verify that the authenticator is bio-capable and
   * not blocked for bio matching.
   *
   * @param requestTemporaryPin after successful match generate a temporary PIN
   * @param checkOnly check verification state of biometrics, don't perform UV
   * @return temporary pin if requestTemporaryPin is true, otherwise null.
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws InvalidPinException in case of unsuccessful match
   * @throws IllegalArgumentException in case of invalid key configuration
   * @throws UnsupportedOperationException in case bio specific verification is not supported
   */
  @Nullable
  public byte[] verifyUv(boolean requestTemporaryPin, boolean checkOnly)
      throws IOException, ApduException, com.yubico.yubikit.core.application.InvalidPinException {
    if (requestTemporaryPin && checkOnly) {
      throw new IllegalArgumentException(
          "Cannot request temporary pin when doing check-only verification");
    }

    try {
      final int TAG_GET_TEMPORARY_PIN = 0x02;
      final int TAG_VERIFY_UV = 0x03;
      byte[] data = null;
      if (!checkOnly) {
        if (requestTemporaryPin) {
          data = new Tlv(TAG_GET_TEMPORARY_PIN, null).getBytes();
        } else {
          data = new Tlv(TAG_VERIFY_UV, null).getBytes();
        }
      }

      byte[] response = protocol.sendAndReceive(new Apdu(0, INS_VERIFY, 0, SLOT_OCC_AUTH, data));
      return requestTemporaryPin ? response : null;
    } catch (ApduException e) {
      if (e.getSw() == SW.REFERENCED_DATA_NOT_FOUND) {
        throw new UnsupportedOperationException(
            "Biometric verification not supported by this YubiKey");
      }
      int retries = getRetriesFromCode(e.getSw());
      if (retries >= 0) {
        throw new com.yubico.yubikit.core.application.InvalidPinException(
            retries, "Fingerprint mismatch, " + retries + " attempts remaining");
      } else {
        // status code returned error, not number of retries
        throw e;
      }
    }
  }

  /**
   * Authenticate YubiKey Bio multi-protocol with temporary PIN.
   *
   * <p>The PIN has to be generated by calling {@link #verifyUv(boolean, boolean)} and is valid only
   * for operations during this session and depending on slot {@link PinPolicy}.
   *
   * <p>Before calling this method, clients must verify that the authenticator is bio-capable and
   * not blocked for bio matching.
   *
   * @param pin temporary pin
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws InvalidPinException in case of unsuccessful match
   * @throws IllegalArgumentException in case of invalid key configuration
   * @throws UnsupportedOperationException in case bio specific verification is not supported
   */
  public void verifyTemporaryPin(byte[] pin)
      throws IOException, ApduException, com.yubico.yubikit.core.application.InvalidPinException {
    if (pin.length != TEMPORARY_PIN_LEN) {
      throw new IllegalArgumentException(
          "Temporary PIN must be exactly " + TEMPORARY_PIN_LEN + " bytes");
    }

    try {
      final int TAG_VERIFY_TEMPORARY_PIN = 0x01;
      protocol.sendAndReceive(
          new Apdu(
              0, INS_VERIFY, 0, SLOT_OCC_AUTH, new Tlv(TAG_VERIFY_TEMPORARY_PIN, pin).getBytes()));
    } catch (ApduException e) {
      if (e.getSw() == SW.REFERENCED_DATA_NOT_FOUND) {
        throw new UnsupportedOperationException(
            "Biometric verification not supported by this YubiKey");
      }
      int retries = getRetriesFromCode(e.getSw());
      if (retries >= 0) {
        throw new com.yubico.yubikit.core.application.InvalidPinException(
            retries, "Invalid temporary PIN, " + retries + " attempts remaining");
      } else {
        // status code returned error, not number of retries
        throw e;
      }
    }
  }

  /**
   * Receive number of attempts left for PIN from YubiKey
   *
   * <p>NOTE: If this command is run in a session where the correct PIN has already been verified,
   * the correct value will not be retrievable, and the value returned may be incorrect if the
   * number of total attempts has been changed from the default.
   *
   * @return number of attempts left
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public int getPinAttempts() throws IOException, ApduException {
    Logger.debug(logger, "Getting PIN attempts");
    if (supports(FEATURE_METADATA)) {
      // If metadata is available, use that
      return getPinMetadata().getAttemptsRemaining();
    }
    try {
      // Null as data will not cause actual tries to decrement
      protocol.sendAndReceive(new Apdu(0, INS_VERIFY, 0, PIN_P2, null));
      // Already verified, no way to know true count
      Logger.debug(logger, "Using cached value, may be incorrect");
      return currentPinAttempts;
    } catch (ApduException e) {
      int retries = getRetriesFromCode(e.getSw());
      if (retries >= 0) {
        currentPinAttempts = retries;
        Logger.debug(logger, "Using value from empty verify");
        return retries;
      } else {
        // status code returned error, not number of retries
        throw e;
      }
    }
  }

  /**
   * Change PIN.
   *
   * @param oldPin old pin for verification
   * @param newPin new pin to set
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws InvalidPinException in case if pin is invalid
   */
  public void changePin(char[] oldPin, char[] newPin)
      throws IOException, ApduException, InvalidPinException {
    Logger.debug(logger, "Changing PIN");
    changeReference(INS_CHANGE_REFERENCE, PIN_P2, oldPin, newPin);
    Logger.info(logger, "New PIN set");
  }

  /**
   * Change PUK.
   *
   * @param oldPuk old puk for verification
   * @param newPuk new puk to set
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws InvalidPinException in case if puk is invalid
   */
  public void changePuk(char[] oldPuk, char[] newPuk)
      throws IOException, ApduException, InvalidPinException {
    Logger.debug(logger, "Changing PUK");
    changeReference(INS_CHANGE_REFERENCE, PUK_P2, oldPuk, newPuk);
    Logger.info(logger, "New PUK set");
  }

  /**
   * Reset a blocked PIN to a new value using the PUK.
   *
   * @param puk puk for verification The default PUK code is 12345678.
   * @param newPin new pin to set
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws InvalidPinException in case if puk is invalid
   */
  public void unblockPin(char[] puk, char[] newPin)
      throws IOException, ApduException, InvalidPinException {
    Logger.debug(logger, "Using PUK to set new PIN");
    changeReference(INS_RESET_RETRY, PIN_P2, puk, newPin);
    Logger.info(logger, "New PIN set");
  }

  /**
   * Set the number of retries available for PIN and PUK entry.
   *
   * <p>This method requires authentication {@link #authenticate} and verification with pin {@link
   * #verifyPin(char[])}}.
   *
   * @param pinAttempts the number of attempts to allow for PIN entry before blocking the PIN
   * @param pukAttempts the number of attempts to allow for PUK entry before blocking the PUK
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public void setPinAttempts(int pinAttempts, int pukAttempts) throws IOException, ApduException {
    Logger.debug(logger, "Setting PIN/PUK attempts ({}, {})", pinAttempts, pukAttempts);
    protocol.sendAndReceive(new Apdu(0, INS_SET_PIN_RETRIES, pinAttempts, pukAttempts, null));
    maxPinAttempts = pinAttempts;
    currentPinAttempts = pinAttempts;
    Logger.info(logger, "PIN/PUK attempts set");
  }

  /**
   * Reads metadata about the PIN, such as total number of retries, attempts left, and if the PIN
   * has been changed from the default value.
   *
   * <p>This functionality requires support for {@link #FEATURE_METADATA}, available on YubiKey 5.3
   * or later.
   *
   * @return metadata about the PIN
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public PinMetadata getPinMetadata() throws IOException, ApduException {
    Logger.debug(logger, "Getting PIN metadata");
    return getPinPukMetadata(PIN_P2);
  }

  /**
   * Reads metadata about the PUK, such as total number of retries, attempts left, and if the PUK
   * has been changed from the default value.
   *
   * <p>This functionality requires support for {@link #FEATURE_METADATA}, available on YubiKey 5.3
   * or later.
   *
   * @return metadata about the PUK
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public PinMetadata getPukMetadata() throws IOException, ApduException {
    Logger.debug(logger, "Getting PUK metadata");
    return getPinPukMetadata(PUK_P2);
  }

  private PinMetadata getPinPukMetadata(byte p2) throws IOException, ApduException {
    require(FEATURE_METADATA);
    Map<Integer, byte[]> data =
        Tlvs.decodeMap(protocol.sendAndReceive(new Apdu(0, INS_GET_METADATA, 0, p2, null)));
    byte[] retries = data.get(TAG_METADATA_RETRIES);
    return new PinMetadata(
        data.get(TAG_METADATA_IS_DEFAULT)[0] != 0,
        retries[INDEX_RETRIES_TOTAL],
        retries[INDEX_RETRIES_REMAINING]);
  }

  /**
   * Reads metadata about the card management key.
   *
   * <p>This functionality requires support for {@link #FEATURE_METADATA}, available on YubiKey 5.3
   * or later.
   *
   * @return metadata about the card management key, such as the Touch policy and if the default
   *     value has been changed
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public ManagementKeyMetadata getManagementKeyMetadata() throws IOException, ApduException {
    Logger.debug(logger, "Getting management key metadata");
    require(FEATURE_METADATA);
    Map<Integer, byte[]> data =
        Tlvs.decodeMap(
            protocol.sendAndReceive(new Apdu(0, INS_GET_METADATA, 0, SLOT_CARD_MANAGEMENT, null)));
    return new ManagementKeyMetadata(
        data.containsKey(TAG_METADATA_ALGO)
            ? ManagementKeyType.fromValue(data.get(TAG_METADATA_ALGO)[0])
            : ManagementKeyType.TDES,
        data.get(TAG_METADATA_IS_DEFAULT)[0] != 0,
        TouchPolicy.fromValue(data.get(TAG_METADATA_POLICY)[INDEX_TOUCH_POLICY]));
  }

  /** Get card management key type. */
  public ManagementKeyType getManagementKeyType() {
    return managementKeyType;
  }

  /**
   * Reads metadata about the private key stored in a slot.
   *
   * <p>This functionality requires support for {@link #FEATURE_METADATA}, available on YubiKey 5.3
   * or later.
   *
   * @param slot the slot to read metadata about
   * @return metadata about a slot
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public SlotMetadata getSlotMetadata(Slot slot) throws IOException, ApduException {
    Logger.debug(logger, "Getting metadata for slot {}", slot);
    require(FEATURE_METADATA);
    Map<Integer, byte[]> data =
        Tlvs.decodeMap(protocol.sendAndReceive(new Apdu(0, INS_GET_METADATA, 0, slot.value, null)));
    byte[] policy = data.get(TAG_METADATA_POLICY);
    return new SlotMetadata(
        KeyType.fromValue(data.get(TAG_METADATA_ALGO)[0]),
        PinPolicy.fromValue(policy[INDEX_PIN_POLICY]),
        TouchPolicy.fromValue(policy[INDEX_TOUCH_POLICY]),
        data.get(TAG_METADATA_ORIGIN)[0] == ORIGIN_GENERATED,
        data.get(TAG_METADATA_PUBLIC_KEY));
  }

  /**
   * Reads the X.509 certificate stored in a slot.
   *
   * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
   * @return certificate instance
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   */
  public X509Certificate getCertificate(Slot slot)
      throws IOException, ApduException, BadResponseException {
    Logger.debug(logger, "Reading certificate in slot {}", slot);
    byte[] objectData = getObject(slot.objectId);

    Map<Integer, byte[]> certData = Tlvs.decodeMap(objectData);
    byte[] certInfo = certData.get(TAG_CERT_INFO);
    byte[] cert = certData.get(TAG_CERTIFICATE);

    boolean isCompressed = certInfo != null && certInfo.length > 0 && certInfo[0] != 0;
    if (isCompressed) {
      try {
        cert = GzipUtils.decompress(cert);
      } catch (IOException e) {
        throw new BadResponseException("Failed to decompress certificate", e);
      }
    }

    try {
      return parseCertificate(cert);
    } catch (CertificateException e) {
      throw new BadResponseException("Failed to parse certificate: ", e);
    }
  }

  /**
   * Writes an X.509 certificate to a slot on the YubiKey. This method requires authentication
   * {@link #authenticate}.
   *
   * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
   * @param certificate certificate to write
   * @param compress If true the certificate will be compressed before being stored on the YubiKey
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public void putCertificate(Slot slot, X509Certificate certificate, boolean compress)
      throws IOException, ApduException {
    byte[] certBytes;
    byte[] certInfo = {compress ? (byte) 0x01 : (byte) 0x00};
    Logger.debug(logger, "Storing {}certificate in slot {}", compress ? "compressed " : "", slot);
    try {
      certBytes = certificate.getEncoded();
    } catch (CertificateEncodingException e) {
      throw new IllegalArgumentException("Failed to get encoded version of certificate", e);
    }

    if (compress) {
      certBytes = GzipUtils.compress(certBytes);
    }

    Map<Integer, byte[]> requestTlv = new LinkedHashMap<>();
    requestTlv.put(TAG_CERTIFICATE, certBytes);
    requestTlv.put(TAG_CERT_INFO, certInfo);
    requestTlv.put(TAG_LRC, null);
    putObject(slot.objectId, Tlvs.encodeMap(requestTlv));
  }

  /**
   * Writes an uncompressed X.509 certificate to a slot on the YubiKey. This method requires
   * authentication {@link #authenticate}.
   *
   * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
   * @param certificate certificate to write
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public void putCertificate(Slot slot, X509Certificate certificate)
      throws IOException, ApduException {
    putCertificate(slot, certificate, false);
  }

  /**
   * Creates an attestation certificate for a private key which was generated on the YubiKey.
   *
   * <p>This functionality requires support for {@link #FEATURE_ATTESTATION}, available on YubiKey
   * 4.3 or later.
   *
   * <p>A high level description of the thinking and how this can be used can be found at <a
   * href="https://developers.yubico.com/PIV/Introduction/PIV_attestation.html">https://developers.yubico.com/PIV/Introduction/PIV_attestation.html</a>
   * Attestation works through a special key slot called "f9" this comes pre-loaded from factory
   * with a key and cert signed by Yubico, but can be overwritten. After a key has been generated in
   * a normal slot it can be attested by this special key
   *
   * <p>This method requires authentication {@link #authenticate} This method requires key to be
   * generated on slot {@link #generateKey(Slot, KeyType, PinPolicy, TouchPolicy)}
   *
   * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
   * @return an attestation certificate for the key in the given slot
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   */
  public X509Certificate attestKey(Slot slot)
      throws IOException, ApduException, BadResponseException {
    require(FEATURE_ATTESTATION);
    try {
      byte[] responseData = protocol.sendAndReceive(new Apdu(0, INS_ATTEST, slot.value, 0, null));
      Logger.debug(logger, "Attested key in slot {}", slot);
      return parseCertificate(responseData);
    } catch (ApduException e) {
      if (SW.INCORRECT_PARAMETERS == e.getSw()) {
        throw new ApduException(
            e.getData(),
            e.getSw(),
            String.format(Locale.ROOT, "Make sure that key is generated on slot %02X", slot.value));
      }
      throw e;
    } catch (CertificateException e) {
      throw new BadResponseException("Failed to parse certificate", e);
    }
  }

  /**
   * Deletes a certificate from the YubiKey. This method requires authentication {@link
   * #authenticate}
   *
   * <p>Note: This does NOT delete any corresponding private key.
   *
   * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public void deleteCertificate(Slot slot) throws IOException, ApduException {
    Logger.debug(logger, "Deleting certificate in slot {}", slot);
    putObject(slot.objectId, null);
  }

  /* Parses a PublicKey from data returned from a YubiKey. */
  static PublicKeyValues parsePublicKeyFromDevice(KeyType keyType, byte[] encoded) {
    Map<Integer, byte[]> dataObjects = Tlvs.decodeMap(encoded);

    if (keyType.params.algorithm == KeyType.Algorithm.RSA) {
      BigInteger modulus = new BigInteger(1, dataObjects.get(0x81));
      BigInteger exponent = new BigInteger(1, dataObjects.get(0x82));
      return new PublicKeyValues.Rsa(modulus, exponent);
    } else {
      if (keyType == KeyType.ED25519 || keyType == KeyType.X25519) {
        return new PublicKeyValues.Cv25519(
            ((KeyType.EcKeyParams) keyType.params).getCurveParams(), dataObjects.get(0x86));
      }
      return PublicKeyValues.Ec.fromEncodedPoint(
          ((KeyType.EcKeyParams) keyType.params).getCurveParams(), dataObjects.get(0x86));
    }
  }

  /**
   * Checks if a given firmware version of YubiKey supports a specific key type with given policies.
   *
   * @param keyType the type of key to check
   * @param pinPolicy the PIN policy to check
   * @param touchPolicy the touch policy to check
   * @param generate true to check if key generation is supported, false to check key import.
   */
  public void checkKeySupport(
      KeyType keyType, PinPolicy pinPolicy, TouchPolicy touchPolicy, boolean generate) {
    if (version.major == 0) {
      return;
    }

    if (keyType == KeyType.ED25519 || keyType == KeyType.X25519) {
      require(FEATURE_CV25519);
    }
    if (keyType == KeyType.ECCP384) {
      require(FEATURE_P384);
    }
    if (pinPolicy != PinPolicy.DEFAULT || touchPolicy != TouchPolicy.DEFAULT) {
      require(FEATURE_USAGE_POLICY);
      if (touchPolicy == TouchPolicy.CACHED) {
        require(FEATURE_TOUCH_CACHED);
      }
    }

    // ROCA
    if (keyType.params.algorithm == KeyType.Algorithm.RSA) {
      if (generate) {
        require(FEATURE_RSA_GENERATION);
      }
      if (keyType.params.bitLength == 3072 || keyType.params.bitLength == 4096) {
        require(FEATURE_RSA3072_RSA4096);
      }
    }

    // FIPS
    if (version.isAtLeast(4, 4, 0) && version.isLessThan(4, 5, 0)) {
      if (keyType == KeyType.RSA1024) {
        throw new UnsupportedOperationException("RSA 1024 is not supported on YubiKey FIPS");
      }
      if (pinPolicy == PinPolicy.NEVER) {
        throw new UnsupportedOperationException("PinPolicy.NEVER is not allowed on YubiKey FIPS");
      }
    }
  }

  /**
   * Generates a new key pair within the YubiKey. This method requires verification with pin {@link
   * #verifyPin}} and authentication with management key {@link #authenticate}.
   *
   * <p>RSA key types require {@link #FEATURE_RSA_GENERATION}, available on YubiKeys OTHER THAN
   * 4.2.6-4.3.4. KeyType P348 requires {@link #FEATURE_P384}, available on YubiKey 4 or later.
   * PinPolicy or TouchPolicy other than default require {@link #FEATURE_USAGE_POLICY}, available on
   * YubiKey 4 or later. TouchPolicy.CACHED requires {@link #FEATURE_TOUCH_CACHED}, available on
   * YubiKey 4.3 or later.
   *
   * <p>NOTE: YubiKey FIPS does not allow RSA1024 nor PinProtocol.NEVER. NOTE: This method will be
   * renamed to generateKey in the next major version release of this library.
   *
   * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
   * @param keyType which algorithm is used for key generation {@link KeyType}
   * @param pinPolicy the PIN policy for using the private key
   * @param touchPolicy the touch policy for using the private key
   * @return the public key of the generated key pair
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   */
  public PublicKeyValues generateKeyValues(
      Slot slot, KeyType keyType, PinPolicy pinPolicy, TouchPolicy touchPolicy)
      throws IOException, ApduException, BadResponseException {
    checkKeySupport(keyType, pinPolicy, touchPolicy, true);

    Map<Integer, byte[]> tlvs = new LinkedHashMap<>();
    tlvs.put(TAG_GEN_ALGORITHM, new byte[] {keyType.value});
    if (pinPolicy != PinPolicy.DEFAULT) {
      tlvs.put(TAG_PIN_POLICY, new byte[] {(byte) pinPolicy.value});
    }
    if (touchPolicy != TouchPolicy.DEFAULT) {
      tlvs.put(TAG_TOUCH_POLICY, new byte[] {(byte) touchPolicy.value});
    }

    Logger.debug(
        logger, "Generating key with pin_policy={}, touch_policy={}", pinPolicy, touchPolicy);
    byte[] response =
        protocol.sendAndReceive(
            new Apdu(
                0,
                INS_GENERATE_ASYMMETRIC,
                0,
                slot.value,
                new Tlv((byte) 0xac, Tlvs.encodeMap(tlvs)).getBytes()));
    Logger.info(logger, "Private key generated in slot {} of type {}", slot, keyType);
    // Tag '7F49' contains data objects for RSA or ECC
    return parsePublicKeyFromDevice(keyType, Tlvs.unpackValue(0x7F49, response));
  }

  /**
   * Generates a new key pair within the YubiKey. This method requires verification with pin {@link
   * #verifyPin}} and authentication with management key {@link #authenticate}.
   *
   * <p>RSA key types require {@link #FEATURE_RSA_GENERATION}, available on YubiKeys OTHER THAN
   * 4.2.6-4.3.4. KeyType P348 requires {@link #FEATURE_P384}, available on YubiKey 4 or later.
   * PinPolicy or TouchPolicy other than default require {@link #FEATURE_USAGE_POLICY}, available on
   * YubiKey 4 or later. TouchPolicy.CACHED requires {@link #FEATURE_TOUCH_CACHED}, available on
   * YubiKey 4.3 or later.
   *
   * <p>NOTE: YubiKey FIPS does not allow RSA1024 nor PinProtocol.NEVER.
   *
   * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
   * @param keyType which algorithm is used for key generation {@link KeyType}
   * @param pinPolicy the PIN policy for using the private key
   * @param touchPolicy the touch policy for using the private key
   * @return the public key of the generated key pair
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   * @deprecated use generateKeyValues instead, which will replace this method in the next major
   *     version release
   */
  @Deprecated
  public PublicKey generateKey(
      Slot slot, KeyType keyType, PinPolicy pinPolicy, TouchPolicy touchPolicy)
      throws IOException, ApduException, BadResponseException {
    try {
      return generateKeyValues(slot, keyType, pinPolicy, touchPolicy).toPublicKey();
    } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Import a private key into a slot. This method requires authentication {@link #authenticate}.
   *
   * <p>KeyType P348 requires {@link #FEATURE_P384}, available on YubiKey 4 or later. PinPolicy or
   * TouchPolicy other than default require {@link #FEATURE_USAGE_POLICY}, available on YubiKey 4 or
   * later.
   *
   * <p>NOTE: YubiKey FIPS does not allow RSA1024 nor PinProtocol.NEVER.
   *
   * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
   * @param key the private key to import
   * @param pinPolicy the PIN policy for using the private key
   * @param touchPolicy the touch policy for using the private key
   * @return the KeyType value of the imported key
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public KeyType putKey(
      Slot slot, PrivateKeyValues key, PinPolicy pinPolicy, TouchPolicy touchPolicy)
      throws IOException, ApduException {
    KeyType keyType = KeyType.fromKeyParams(key);
    checkKeySupport(keyType, pinPolicy, touchPolicy, false);

    KeyType.KeyParams params = keyType.params;
    Map<Integer, byte[]> tlvs = new LinkedHashMap<>();

    switch (params.algorithm) {
      case RSA:
        int byteLength = params.bitLength / 8 / 2;
        PrivateKeyValues.Rsa values = (PrivateKeyValues.Rsa) key;
        tlvs.put(0x01, intToLength(values.getPrimeP(), byteLength)); // p
        tlvs.put(0x02, intToLength(values.getPrimeQ(), byteLength)); // q
        tlvs.put(
            0x03,
            intToLength(Objects.requireNonNull(values.getPrimeExponentP()), byteLength)); // dmp1
        tlvs.put(
            0x04,
            intToLength(Objects.requireNonNull(values.getPrimeExponentQ()), byteLength)); // dmq1
        tlvs.put(
            0x05,
            intToLength(Objects.requireNonNull(values.getCrtCoefficient()), byteLength)); // iqmp
        break;
      case EC:
        PrivateKeyValues.Ec ecPrivateKey = (PrivateKeyValues.Ec) key;
        tlvs.put(
            keyType == KeyType.ED25519 ? 0x07 : keyType == KeyType.X25519 ? 0x08 : 0x06,
            ecPrivateKey.getSecret()); // s
        break;
    }

    if (pinPolicy != PinPolicy.DEFAULT) {
      tlvs.put(TAG_PIN_POLICY, new byte[] {(byte) pinPolicy.value});
    }
    if (touchPolicy != TouchPolicy.DEFAULT) {
      tlvs.put(TAG_TOUCH_POLICY, new byte[] {(byte) touchPolicy.value});
    }

    Logger.debug(
        logger, "Importing key with pin_policy={}, touch_policy={}", pinPolicy, touchPolicy);
    protocol.sendAndReceive(
        new Apdu(0, INS_IMPORT_KEY, keyType.value, slot.value, Tlvs.encodeMap(tlvs)));
    Logger.info(logger, "Private key imported in slot {} of type {}", slot, keyType);
    return keyType;
  }

  /**
   * Import a private key into a slot. This method requires authentication {@link #authenticate}.
   *
   * <p>KeyType P348 requires {@link #FEATURE_P384}, available on YubiKey 4 or later. PinPolicy or
   * TouchPolicy other than default require {@link #FEATURE_USAGE_POLICY}, available on YubiKey 4 or
   * later.
   *
   * <p>NOTE: YubiKey FIPS does not allow RSA1024 nor PinProtocol.NEVER.
   *
   * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
   * @param key the private key to import
   * @param pinPolicy the PIN policy for using the private key
   * @param touchPolicy the touch policy for using the private key
   * @return the KeyType value of the imported key
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @deprecated use {@link #putKey(Slot, PrivateKeyValues, PinPolicy, TouchPolicy)} instead
   */
  @Deprecated
  public KeyType putKey(Slot slot, PrivateKey key, PinPolicy pinPolicy, TouchPolicy touchPolicy)
      throws IOException, ApduException {
    return putKey(slot, PrivateKeyValues.fromPrivateKey(key), pinPolicy, touchPolicy);
  }

  /**
   * Move key from one slot to another. The source slot must not be {@link Slot#ATTESTATION} and the
   * destination slot must be empty. This method requires authentication with management key {@link
   * #authenticate}.
   *
   * @param sourceSlot Slot to move the key from
   * @param destinationSlot Slot to move the key to
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @see Slot
   */
  public void moveKey(Slot sourceSlot, Slot destinationSlot) throws IOException, ApduException {
    require(FEATURE_MOVE_KEY);
    if (sourceSlot == Slot.ATTESTATION) {
      throw new IllegalArgumentException("Can't move Attestation key (F9)");
    }
    Logger.debug(
        logger,
        "Move key from {} to {}",
        sourceSlot.getStringAlias(),
        destinationSlot.getStringAlias());
    protocol.sendAndReceive(
        new Apdu(0, INS_MOVE_KEY, destinationSlot.value, sourceSlot.value, null));
    Logger.info(
        logger,
        "Moved key from {} to {}",
        sourceSlot.getStringAlias(),
        destinationSlot.getStringAlias());
  }

  /**
   * Delete key from slot. This method requires authentication with management key {@link
   * #authenticate}.
   *
   * @param slot Slot to delete key from.
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @see Slot
   */
  public void deleteKey(Slot slot) throws IOException, ApduException {
    require(FEATURE_MOVE_KEY);
    Logger.debug(logger, "Delete key from {}", slot.getStringAlias());
    protocol.sendAndReceive(new Apdu(0, INS_MOVE_KEY, 0xff, slot.value, null));
    Logger.info(logger, "Deleted key from {}", slot.getStringAlias());
  }

  /**
   * Read a data object from the YubiKey.
   *
   * @param objectId the ID of the object to read, see {@link ObjectId}.
   * @return the stored data object contents
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   * @throws BadResponseException in case of incorrect YubiKey response
   */
  public byte[] getObject(int objectId) throws IOException, ApduException, BadResponseException {
    Logger.debug(logger, "Reading data from object slot {}", Integer.toString(objectId, 16));
    byte[] requestData = new Tlv(TAG_OBJ_ID, ObjectId.getBytes(objectId)).getBytes();
    byte[] responseData =
        protocol.sendAndReceive(new Apdu(0, INS_GET_DATA, 0x3f, 0xff, requestData));
    return Tlvs.unpackValue(TAG_OBJ_DATA, responseData);
  }

  /**
   * Write a data object to the YubiKey.
   *
   * @param objectId the ID of the object to write, see {@link ObjectId}.
   * @param objectData the data object contents to write
   * @throws IOException in case of connection error
   * @throws ApduException in case of an error response from the YubiKey
   */
  public void putObject(int objectId, @Nullable byte[] objectData)
      throws IOException, ApduException {
    Logger.debug(logger, "Writing data to object slot {}", Integer.toString(objectId, 16));
    Map<Integer, byte[]> tlvs = new LinkedHashMap<>();
    tlvs.put(TAG_OBJ_ID, ObjectId.getBytes(objectId));
    tlvs.put(TAG_OBJ_DATA, objectData);
    protocol.sendAndReceive(new Apdu(0, INS_PUT_DATA, 0x3f, 0xff, Tlvs.encodeMap(tlvs)));
  }

  /*
   * Parses x509 certificate object from byte array
   */
  private X509Certificate parseCertificate(byte[] data) throws CertificateException {
    InputStream stream = new ByteArrayInputStream(data);
    CertificateFactory cf = CertificateFactory.getInstance("X.509");
    return (X509Certificate) cf.generateCertificate(stream);
  }

  private void changeReference(byte instruction, byte p2, char[] value1, char[] value2)
      throws IOException, ApduException, InvalidPinException {
    byte[] pinBytes = pinBytes(value1, value2);
    try {
      protocol.sendAndReceive(new Apdu(0, instruction, 0, p2, pinBytes));
    } catch (ApduException e) {
      int retries = getRetriesFromCode(e.getSw());
      if (retries >= 0) {
        if (p2 == PIN_P2) {
          currentPinAttempts = retries;
        }
        throw new InvalidPinException(retries);
      } else {
        throw e;
      }
    } finally {
      Arrays.fill(pinBytes, (byte) 0);
    }
  }

  private void blockPin() throws IOException, ApduException {
    // Note: that 15 is the highest value that will be returned even if remaining tries is higher.
    Logger.debug(logger, "Verify PIN with invalid attempts until blocked");
    int counter = getPinAttempts();
    while (counter > 0) {
      try {
        verifyPin(new char[0]);
      } catch (InvalidPinException e) {
        counter = e.getAttemptsRemaining();
      }
    }

    Logger.debug(logger, "PIN is blocked");
  }

  private void blockPuk() throws IOException, ApduException {
    // A failed unblock pin will return number of PUK tries left and also uses one try.
    Logger.debug(logger, "Verify PUK with invalid attempts until blocked");
    int counter = 1;
    while (counter > 0) {
      try {
        changeReference(INS_RESET_RETRY, PIN_P2, new char[0], new char[0]);
      } catch (InvalidPinException e) {
        counter = e.getAttemptsRemaining();
      }
    }
    Logger.debug(logger, "PUK is blocked");
  }

  private static byte[] pinBytes(char[] pin) {
    ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(pin));
    try {
      int byteLen = byteBuffer.limit() - byteBuffer.position();
      if (byteLen > PIN_LEN) {
        throw new IllegalArgumentException("PIN/PUK must be no longer than 8 bytes");
      }
      byte[] alignedPinByte = Arrays.copyOf(byteBuffer.array(), PIN_LEN);
      Arrays.fill(alignedPinByte, byteLen, PIN_LEN, (byte) 0xff);
      return alignedPinByte;
    } finally {
      Arrays.fill(byteBuffer.array(), (byte) 0); // clear sensitive data
    }
  }

  private static byte[] pinBytes(char[] pin1, char[] pin2) {
    ByteArrayOutputStream stream = new ByteArrayOutputStream();
    byte[] pinBytes1 = pinBytes(pin1);
    byte[] pinBytes2 = pinBytes(pin2);
    try {
      stream.write(pinBytes1);
      stream.write(pinBytes2);
      return stream.toByteArray();
    } catch (IOException e) {
      throw new RuntimeException(e); // This shouldn't happen
    } finally {
      Arrays.fill(pinBytes1, (byte) 0); // clear sensitive data
      Arrays.fill(pinBytes2, (byte) 0); // clear sensitive data
    }
  }

  /*
   * Parses number of left attempts from status code
   */
  private int getRetriesFromCode(int statusCode) {
    if (statusCode == SW.AUTH_METHOD_BLOCKED) {
      return 0;
    }
    if (version.isLessThan(1, 0, 4)) {
      if (statusCode >= 0x6300 && statusCode <= 0x63ff) {
        return statusCode & 0xff;
      }
    } else {
      if (statusCode >= 0x63c0 && statusCode <= 0x63cf) {
        return statusCode & 0xf;
      }
    }
    return -1;
  }
}

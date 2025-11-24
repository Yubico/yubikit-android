/*
 * Copyright (C)2025 Yubico.
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

package com.yubico.yubikit.fido.ctap;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.fido.FidoProtocol;
import com.yubico.yubikit.core.keys.EllipticCurveValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AttestedCredentialData;
import com.yubico.yubikit.fido.webauthn.AuthenticatorData;
import java.io.ByteArrayInputStream;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.slf4j.LoggerFactory;

/**
 * Implementation of the CTAP1 (U2F) specification.
 *
 * <p>This class provides methods for U2F registration and authentication operations using the
 * legacy CTAP1 protocol, also known as FIDO U2F.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html">FIDO
 *     U2F Raw Message Formats</a>
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-nfc-protocol-v1.2-ps-20170411.html">FIDO
 *     NFC Protocol Specification v1.0</a>
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html">FIDO
 *     U2F HID Protocol Specification</a>
 */
public class Ctap1Session extends CtapSession {

  private static final byte CLA = 0x00;
  private static final byte INS_REGISTER = 0x01;
  private static final byte INS_AUTHENTICATE = 0x02;
  private static final byte INS_VERSION = 0x03;

  public static final byte P1_CHECK_ONLY = 0x07;
  public static final byte P1_ENFORCE_USER_PRESENCE = 0x03;

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Ctap1Session.class);

  private final Backend<?> backend;
  private final Version version;

  /**
   * Construct a new Ctap1Session for a given YubiKey.
   *
   * @param device a YubiKeyDevice over NFC or USB
   * @param callback a callback to invoke with the session
   */
  public static void create(
      YubiKeyDevice device, Callback<Result<CtapSession, Exception>> callback) {
    if (device.supportsConnection(FidoConnection.class)) {
      device.requestConnection(
          FidoConnection.class,
          value -> callback.invoke(Result.of(() -> new Ctap1Session(value.getValue()))));
    } else if (device.supportsConnection(SmartCardConnection.class)) {
      device.requestConnection(
          SmartCardConnection.class,
          value -> callback.invoke(Result.of(() -> new Ctap1Session(value.getValue()))));
    } else {
      callback.invoke(
          Result.failure(
              new ApplicationNotAvailableException(
                  "Session does not support any compatible connection type")));
    }
  }

  public static @Nullable Ctap1Session create(YubiKeyConnection connection)
      throws IOException, ApplicationNotAvailableException, IllegalArgumentException {
    if (connection instanceof FidoConnection) {
      try {
        logger.debug("Attempting to create Ctap1Session from FidoConnection");
        return new Ctap1Session((FidoConnection) connection);
      } catch (IOException e) {
        logger.debug("Failed to create Ctap1Session from FidoConnection: {}", e.getMessage());
        return null;
      }
    } else if (connection instanceof SmartCardConnection) {
      try {
        logger.debug("Attempting to create Ctap1Session from SmartCardConnection");
        return new Ctap1Session((SmartCardConnection) connection);
      } catch (IOException | ApplicationNotAvailableException e) {
        logger.debug("Failed to create Ctap1Session from SmartCardConnection: {}", e.getMessage());
        return null;
      }
    } else {
      throw new IllegalArgumentException(
          "Unsupported connection type: "
              + connection.getClass().getName()
              + ". Expected FidoConnection or SmartCardConnection.");
    }
  }

  /**
   * Creates a new CTAP1 session from a SmartCard connection.
   *
   * @param connection a SmartCard/NFC connection
   * @throws IOException if communication with the device fails
   * @throws ApplicationNotAvailableException if the FIDO application is not available
   */
  public Ctap1Session(SmartCardConnection connection)
      throws IOException, ApplicationNotAvailableException {
    super(connection);
    SmartCardProtocol protocol = new SmartCardProtocol(connection);
    // Select FIDO application - using the same AppId as CTAP2
    protocol.select(AppId.FIDO);

    // CTAP1 doesn't have version information accessible via NFC
    this.version = new Version(0, 0, 0);
    this.backend =
        new Backend<SmartCardProtocol>(protocol) {
          @Override
          byte[] sendApdu(byte ins, byte p1, byte[] data) throws IOException, ApduException {
            Apdu apdu = new Apdu(CLA, ins, p1, 0, data);
            return delegate.sendAndReceive(apdu);
          }
        };
    logger.debug("Ctap1Session initialized for SmartCard connection");
  }

  /**
   * Creates a new CTAP1 session from a FIDO connection.
   *
   * @param connection a FIDO HID connection
   * @throws IOException if communication with the device fails
   */
  public Ctap1Session(FidoConnection connection) throws IOException {
    super(connection);
    final FidoProtocol protocol = new FidoProtocol(connection);
    this.version = protocol.getVersion();
    this.backend =
        new Backend<FidoProtocol>(protocol) {
          private static final byte CTAPHID_MSG = (byte) 0x83;

          @Override
          byte[] sendApdu(byte ins, byte p1, byte[] data) throws IOException, ApduException {
            ByteBuffer buffer =
                ByteBuffer.allocate(9 + data.length)
                    .put(CLA)
                    .put(ins)
                    .put(p1)
                    .put((byte) 0)
                    .put((byte) 0) // Extended length Lc high byte
                    .putShort((short) data.length)
                    .put(data)
                    .put((byte) 0) // Le high
                    .put((byte) 0); // Le low (256 bytes expected)

            byte[] response = delegate.sendAndReceive(CTAPHID_MSG, buffer.array(), null);

            // Check status word (last 2 bytes)
            if (response.length < 2) {
              throw new IOException("Response too short");
            }

            short sw =
                (short)
                    (((response[response.length - 2] & 0xFF) << 8)
                        | (response[response.length - 1] & 0xFF));
            byte[] responseData = new byte[response.length - 2];
            System.arraycopy(response, 0, responseData, 0, responseData.length);

            if (sw != SW.OK) {
              throw new ApduException(responseData, sw);
            }

            return responseData;
          }
        };
  }

  @Override
  public void close() throws IOException {
    backend.close();
  }

  /**
   * Gets the version of the YubiKey firmware.
   *
   * <p>For USB connections, this returns the version from the HID device. For NFC connections,
   * version information is not available and returns 0.0.0.
   *
   * @return the YubiKey firmware version
   */
  @Override
  public Version getVersion() {
    return version;
  }

  /**
   * Sends an APDU command and receives the response. This is a low-level method mainly used
   * internally.
   *
   * @return the response data
   * @throws IOException if communication fails
   * @throws ApduException if the command returns an error status
   */
  private byte[] sendApdu(byte ins, int p1, byte[] data) throws IOException, ApduException {
    return backend.sendApdu(ins, (byte) (p1 & 0xff), data);
  }

  /**
   * Gets the U2F version implemented by the authenticator. The only version specified is "U2F_V2".
   *
   * @return a U2F version string
   * @throws IOException if communication fails
   * @throws ApduException if the command returns an error status
   */
  public String getU2fVersion() throws IOException, ApduException {
    byte[] response = sendApdu(INS_VERSION, 0, new byte[0]);
    return new String(response, StandardCharsets.UTF_8);
  }

  /**
   * Registers a new U2F credential.
   *
   * @param clientParam SHA256 hash of the ClientData used for the request
   * @param appParam SHA256 hash of the app ID used for the request
   * @return the registration response from the authenticator
   * @throws IOException if communication fails
   * @throws ApduException if the command returns an error status
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#registration-messages">Registration
   *     Messages</a>
   */
  public RegistrationData register(byte[] clientParam, byte[] appParam)
      throws IOException, ApduException {
    if (clientParam.length != 32) {
      throw new IllegalArgumentException("clientParam must be 32 bytes");
    }
    if (appParam.length != 32) {
      throw new IllegalArgumentException("appParam must be 32 bytes");
    }

    ByteBuffer buffer =
        ByteBuffer.allocate(clientParam.length + appParam.length).put(clientParam).put(appParam);

    byte[] response = sendApdu(INS_REGISTER, 0, buffer.array());
    return new RegistrationData(response);
  }

  /**
   * Authenticates a previously registered credential.
   *
   * @param clientParam SHA256 hash of the ClientData used for the request
   * @param appParam SHA256 hash of the app ID used for the request
   * @param keyHandle the binary key handle of the credential
   * @param checkOnly true to send a "check-only" request to determine if a key handle is known
   * @return the authentication response from the authenticator
   * @throws IOException if communication fails
   * @throws ApduException if the command returns an error status
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html#authentication-messages">Authentication
   *     Messages</a>
   */
  public SignatureData authenticate(
      byte[] clientParam, byte[] appParam, byte[] keyHandle, boolean checkOnly)
      throws IOException, ApduException, ClientError {
    if (clientParam.length != 32) {
      throw new IllegalArgumentException("clientParam must be 32 bytes");
    }
    if (appParam.length != 32) {
      throw new IllegalArgumentException("appParam must be 32 bytes");
    }

    ByteBuffer buffer =
        ByteBuffer.allocate(clientParam.length + appParam.length + 1 + keyHandle.length)
            .put(clientParam)
            .put(appParam)
            .put((byte) keyHandle.length)
            .put(keyHandle);
    byte p1 = checkOnly ? P1_CHECK_ONLY : P1_ENFORCE_USER_PRESENCE;

    try {
      byte[] response = sendApdu(INS_AUTHENTICATE, p1, buffer.array());
      return new SignatureData(response);
    } catch (ApduException e) {

      if (checkOnly && e.getSw() == SW.CONDITIONS_NOT_SATISFIED) {
        // 0x07 ("check-only"): if the control byte is set to 0x07 by the FIDO Client, the U2F token
        // is supposed to simply check whether the provided key handle was originally created by
        // this token, and whether it was created for the provided application parameter. If so, the
        // U2F token MUST respond with an authentication response
        // message:error:test-of-user-presence-required (note that despite the name this signals a
        // success condition). If the key handle was not created by this U2F token, or if it was
        // created for a different application parameter, the token MUST respond with an
        // authentication response message:error:bad-key-handle.
        throw new ClientError(
            ClientError.Code.DEVICE_INELIGIBLE, "Credential in exclude list already registered");
      }

      throw e;
    }
  }

  /**
   * Binary response data for a CTAP1 (U2F) registration.
   *
   * <p>This class parses and provides access to the components of a U2F registration response,
   * including the credential public key, key handle, attestation certificate, and signature.
   */
  public static class RegistrationData {
    private static final byte RESERVED_BYTE = 0x05;

    private final byte[] data;
    private final byte[] publicKey;
    private final byte[] keyHandle;
    private final byte[] certificate;
    private final byte[] signature;

    /**
     * Parses a RegistrationData from raw bytes.
     *
     * @param data the binary response data from the authenticator
     * @throws IllegalArgumentException if the data is malformed
     */
    public RegistrationData(byte[] data) {
      this.data = Arrays.copyOf(data, data.length);

      ByteBuffer reader = ByteBuffer.wrap(data);

      // Check reserved byte
      if (reader.get() != RESERVED_BYTE) {
        throw new IllegalArgumentException("Reserved byte != 0x05");
      }

      // Read public key (65 bytes: 0x04 + 32-byte X + 32-byte Y for P-256)
      publicKey = new byte[65];
      reader.get(publicKey);

      // Read key handle length and key handle
      int keyHandleLength = reader.get() & 0xFF;
      keyHandle = new byte[keyHandleLength];
      reader.get(keyHandle);

      // Parse certificate
      certificate = parseCertificate(reader);

      // Remaining bytes are the signature
      signature = new byte[reader.remaining()];
      reader.get(signature);
    }

    /**
     * Parses an X.509 certificate from the buffer.
     *
     * @param reader the buffer to read from
     * @return the DER-encoded certificate bytes
     */
    private byte[] parseCertificate(ByteBuffer reader) {
      int startPos = reader.position();
      byte[] remaining = new byte[reader.remaining()];
      reader.get(remaining);

      // Parse the first TLV (the certificate)
      Tlv certTlv = Tlvs.decodeList(remaining).get(0);
      byte[] cert = certTlv.getBytes();

      // Move the buffer position forward by the certificate length
      reader.position(startPos + cert.length);
      return cert;
    }

    /**
     * Gets the raw binary data.
     *
     * @return the complete registration data bytes
     */
    public byte[] getData() {
      return Arrays.copyOf(data, data.length);
    }

    /**
     * Gets the credential public key in uncompressed format (0x04 + X + Y).
     *
     * @return the 65-byte public key
     */
    public byte[] getPublicKey() {
      return Arrays.copyOf(publicKey, publicKey.length);
    }

    /**
     * Gets the credential key handle.
     *
     * @return the key handle bytes
     */
    public byte[] getKeyHandle() {
      return Arrays.copyOf(keyHandle, keyHandle.length);
    }

    /**
     * Gets the attestation certificate in DER format.
     *
     * @return the DER-encoded X.509 certificate
     */
    public byte[] getCertificate() {
      return Arrays.copyOf(certificate, certificate.length);
    }

    /**
     * Gets the attestation signature.
     *
     * @return the signature bytes
     */
    public byte[] getSignature() {
      return Arrays.copyOf(signature, signature.length);
    }

    /**
     * Parses the attestation certificate as an X509Certificate object.
     *
     * @return the parsed certificate
     * @throws CertificateException if the certificate cannot be parsed
     */
    public X509Certificate parseCertificate() throws CertificateException {
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(certificate));
    }

    /**
     * Parses the public key as a PublicKey object.
     *
     * @return the parsed public key
     * @throws NoSuchAlgorithmException if EC algorithm is not available
     * @throws InvalidKeySpecException if the key data is invalid
     */
    public PublicKey parsePublicKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
      return PublicKeyValues.Ec.fromEncodedPoint(EllipticCurveValues.SECP256R1, publicKey)
          .toPublicKey();
    }

    /**
     * Verifies the attestation signature.
     *
     * <p>This verifies that the signature was created by the private key corresponding to the
     * certificate's public key, over the correct registration data.
     *
     * @param appParam the SHA256 hash of the app ID
     * @param clientParam the SHA256 hash of the ClientData
     * @throws SignatureException if the signature is invalid
     * @throws CertificateException if the certificate cannot be parsed
     * @throws NoSuchAlgorithmException if required algorithms are not available
     * @throws InvalidKeyException if the certificate's public key is invalid
     */
    public void verify(byte[] appParam, byte[] clientParam)
        throws SignatureException,
            CertificateException,
            NoSuchAlgorithmException,
            InvalidKeyException {
      // Reconstruct the signed data
      // Format: 0x00 || appParam || clientParam || keyHandle || publicKey
      ByteBuffer signedData =
          ByteBuffer.allocate(
                  1 + appParam.length + clientParam.length + keyHandle.length + publicKey.length)
              .put((byte) 0x00)
              .put(appParam)
              .put(clientParam)
              .put(keyHandle)
              .put(publicKey);

      // Parse certificate and verify signature
      X509Certificate cert = parseCertificate();
      Signature sig = Signature.getInstance("SHA256withECDSA");
      sig.initVerify(cert.getPublicKey());
      sig.update(signedData.array());

      if (!sig.verify(signature)) {
        throw new SignatureException("Invalid attestation signature");
      }
    }

    /**
     * Create an AttestationObject from CTAP1 registration data (U2F). Equivalent to Python's
     * AttestationObject.from_ctap1.
     */
    public AttestationObject getAttestation(byte[] appParam) {
      // Flags: UP (0x01) | AT (0x40)
      byte flags = (byte) (0x01 | 0x40);
      int signCount = 0;
      // AAGUID is all zeros for U2F
      byte[] aaguid = new byte[16];
      // Credential ID is the key handle
      byte[] credentialId = getKeyHandle();
      // Convert U2F public key to COSE
      byte[] u2fPublicKey = getPublicKey();
      Map<Integer, Object> coseKey = new HashMap<>();
      coseKey.put(1, 2); // kty: EC2
      coseKey.put(3, -7); // alg: ES256
      coseKey.put(-1, 1); // crv: P-256
      coseKey.put(-2, Arrays.copyOfRange(u2fPublicKey, 1, 33));
      coseKey.put(-3, Arrays.copyOfRange(u2fPublicKey, 33, 65));
      // Build AttestedCredentialData
      AttestedCredentialData credentialData =
          new AttestedCredentialData(aaguid, credentialId, coseKey);
      byte[] credentialDataBytes = credentialData.bytes();

      // Build AuthenticatorData
      AuthenticatorData authData =
          AuthenticatorData.parseFrom(
              ByteBuffer.allocate(32 + 1 + 4 + credentialDataBytes.length)
                  .put(appParam)
                  .put(flags)
                  .putInt(signCount)
                  .put(credentialDataBytes)
                  .rewind());

      // Build attestation statement
      Map<String, Object> attStmt = new HashMap<>();
      attStmt.put("x5c", Collections.singletonList(getCertificate()));
      attStmt.put("sig", getSignature());
      // Return the attestation object
      return new AttestationObject("fido-u2f", authData, attStmt, null, null, null);
    }
  }

  /**
   * Binary response data for a CTAP1 (U2F) authentication.
   *
   * <p>This class parses and provides access to the components of a U2F authentication response,
   * including the user presence byte, signature counter, and cryptographic signature.
   */
  public static class SignatureData {
    private final byte[] data;
    private final byte userPresence;
    private final int counter;
    private final byte[] signature;

    /**
     * Parses a SignatureData from raw bytes.
     *
     * @param data the binary response data from the authenticator
     * @throws IllegalArgumentException if the data is malformed
     */
    public SignatureData(byte[] data) {
      if (data.length < 5) {
        throw new IllegalArgumentException("SignatureData too short");
      }

      this.data = Arrays.copyOf(data, data.length);

      ByteBuffer reader = ByteBuffer.wrap(data);

      // Read user presence byte
      userPresence = reader.get();

      // Read counter (4 bytes, big-endian)
      counter = reader.getInt();

      // Remaining bytes are the signature
      signature = new byte[reader.remaining()];
      reader.get(signature);
    }

    /**
     * Gets the raw binary data.
     *
     * @return the complete signature data bytes
     */
    public byte[] getData() {
      return Arrays.copyOf(data, data.length);
    }

    /**
     * Gets the user presence byte.
     *
     * <p>Bit 0 indicates user presence (1 = present, 0 = not present). Other bits are reserved for
     * future use (RFU).
     *
     * @return the user presence byte
     */
    public byte getUserPresence() {
      return userPresence;
    }

    /**
     * Checks if the user presence flag is set.
     *
     * @return true if the user was present during authentication
     */
    public boolean isUserPresent() {
      return (userPresence & 0x01) != 0;
    }

    /**
     * Gets the signature counter value.
     *
     * <p>This counter is incremented by the authenticator each time it performs an authentication
     * operation. It can be used to detect cloned authenticators.
     *
     * @return the signature counter
     */
    public int getCounter() {
      return counter;
    }

    /**
     * Gets the cryptographic signature.
     *
     * @return the signature bytes in DER format
     */
    public byte[] getSignature() {
      return Arrays.copyOf(signature, signature.length);
    }

    /**
     * Verifies the authentication signature.
     *
     * <p>This verifies that the signature was created by the private key corresponding to the given
     * public key, over the correct authentication data.
     *
     * @param appParam the SHA256 hash of the app ID
     * @param clientParam the SHA256 hash of the ClientData
     * @param publicKey the credential public key to verify against
     * @throws SignatureException if the signature is invalid
     * @throws NoSuchAlgorithmException if required algorithms are not available
     * @throws InvalidKeyException if the public key is invalid
     */
    public void verify(byte[] appParam, byte[] clientParam, PublicKey publicKey)
        throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
      // Reconstruct the signed data
      // Format: appParam || userPresence || counter || clientParam
      ByteBuffer signedData =
          ByteBuffer.allocate(appParam.length + 1 + 4 + clientParam.length)
              .put(appParam)
              .put(userPresence)
              .putInt(counter)
              .put(clientParam);

      // Verify signature
      Signature sig = Signature.getInstance("SHA256withECDSA");
      sig.initVerify(publicKey);
      sig.update(signedData.array());

      if (!sig.verify(signature)) {
        throw new SignatureException("Invalid authentication signature");
      }
    }

    /**
     * Verifies the authentication signature using a raw P-256 public key.
     *
     * <p>This is a convenience method that accepts the raw 65-byte public key format (0x04 +
     * 32-byte X + 32-byte Y) as returned by {@link RegistrationData#getPublicKey()}.
     *
     * @param appParam the SHA256 hash of the app ID
     * @param clientParam the SHA256 hash of the ClientData
     * @param rawPublicKey the raw 65-byte P-256 public key
     * @throws SignatureException if the signature is invalid
     * @throws NoSuchAlgorithmException if required algorithms are not available
     * @throws InvalidKeyException if the public key is invalid
     * @throws IllegalArgumentException if the public key format is invalid
     */
    public void verify(byte[] appParam, byte[] clientParam, byte[] rawPublicKey)
        throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
      if (rawPublicKey.length != 65 || rawPublicKey[0] != 0x04) {
        throw new IllegalArgumentException("Invalid public key format");
      }
      try {
        PublicKey publicKey =
            PublicKeyValues.Ec.fromEncodedPoint(EllipticCurveValues.SECP256R1, rawPublicKey)
                .toPublicKey();
        verify(appParam, clientParam, publicKey);
      } catch (InvalidKeySpecException e) {
        throw new InvalidKeyException("Failed to parse public key", e);
      }
    }
  }

  private abstract static class Backend<T extends Closeable> implements Closeable {
    protected final T delegate;

    private Backend(T delegate) {
      this.delegate = delegate;
    }

    @Override
    public void close() throws IOException {
      delegate.close();
    }

    abstract byte[] sendApdu(byte ins, byte p1, byte[] data) throws IOException, ApduException;
  }
}

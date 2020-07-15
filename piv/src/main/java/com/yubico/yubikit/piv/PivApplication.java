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

package com.yubico.yubikit.piv;

import android.os.Build;
import android.util.SparseArray;

import androidx.annotation.Nullable;

import com.yubico.yubikit.Iso7816Application;
import com.yubico.yubikit.apdu.Apdu;
import com.yubico.yubikit.apdu.Tlv;
import com.yubico.yubikit.apdu.TlvUtils;
import com.yubico.yubikit.apdu.Version;
import com.yubico.yubikit.exceptions.ApduException;
import com.yubico.yubikit.exceptions.ApplicationNotFound;
import com.yubico.yubikit.exceptions.BadRequestException;
import com.yubico.yubikit.exceptions.BadResponseException;
import com.yubico.yubikit.exceptions.NotSupportedOperation;
import com.yubico.yubikit.exceptions.UnexpectedTagException;
import com.yubico.yubikit.exceptions.YubiKeyCommunicationException;
import com.yubico.yubikit.transport.YubiKeySession;
import com.yubico.yubikit.utils.Logger;
import com.yubico.yubikit.utils.StringUtils;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static com.yubico.yubikit.piv.CryptoUtils.publicEccKey;
import static com.yubico.yubikit.piv.CryptoUtils.publicRsaKey;

/**
 * Personal Identity Verification (PIV) interface specified in NIST SP 800-73 document "Cryptographic Algorithms and Key Sizes for PIV".
 * This enables you to perform RSA or ECC sign/decrypt operations using a private key stored on the smartcard, through common interfaces like PKCS#11.
 */
public class PivApplication extends Iso7816Application {
    public static final short APPLICATION_NOT_FOUND_ERROR = 0x6a82;
    public static final short AUTHENTICATION_REQUIRED_ERROR = 0x6982;
    public static final short FILE_NOT_FOUND_ERROR = APPLICATION_NOT_FOUND_ERROR;
    public static final short INCORRECT_VALUES_ERROR = 0x6a80;
    public static final short AUTH_METHOD_BLOCKED = 0x6983;

    private static final int PIN_SIZE = 8;

    // Select aid
    private static final byte[] AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x03, 0x08};

    // Instruction set
    private static final byte INS_VERIFY = 0x20;
    private static final byte INS_CHANGE_REFERENCE = 0x24;
    private static final byte INS_RESET_RETRY = 0x2c;
    private static final byte INS_GENERATE_ASYMMETRIC = 0x47;
    private static final byte INS_AUTHENTICATE = (byte) 0x87;
    private static final byte INS_GET_DATA = (byte) 0xcb;
    private static final byte INS_PUT_DATA = (byte) 0xdb;
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
    private static final int TAG_GEN_ALGORITHM = 0x80;
    private static final int TAG_OBJ_DATA = 0x53;
    private static final int TAG_OBJ_ID = 0x5c;
    private static final int TAG_CERTIFICATE = 0x70;
    private static final int TAG_CERT_INFO = 0x71;
    private static final int TAG_DYN_AUTH = 0x7c;
    private static final int TAG_LRC = 0xfe;
    private static final int TAG_PIN_POLICY = 0xaa;
    private static final int TAG_TOUCH_POLICY = 0xab;

    private static final byte PIN_P2 = (byte) 0x80;
    private static final byte PUK_P2 = (byte) 0x81;

    private static final List<Algorithm> SUPPORTED_ALGORITHMS = Arrays.asList(Algorithm.RSA1024, Algorithm.RSA2048, Algorithm.ECCP256, Algorithm.ECCP384);
    private static final byte[] RSA_HASH_SHA256_PREFIX = new byte[]{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};
    private static final byte TDES = 0x03;


    private Version version;


    /**
     * Create new instance of {@link PivApplication}
     * and selects the application for use
     *
     * @param session session with YubiKey
     * @throws IOException in case of communication error
     */
    public PivApplication(YubiKeySession session) throws IOException, ApduException, ApplicationNotFound {
        super(AID, session);

        try {
            select();

            byte[] versionResponse = sendAndReceive(new Apdu(0, INS_GET_VERSION, 0, 0, null));
            // get firmware version
            version = Version.parse(versionResponse);
        } catch (ApduException e) {
            if (e.getStatusCode() == APPLICATION_NOT_FOUND_ERROR) {
                throw new ApplicationNotFound("PIV application is disabled on this device");
            } else {
                throw e;
            }
        } finally {
            if (version == null) {
                close();
            }
        }
    }

    /**
     * Gets firmware version
     * Note: for YK NEO returns PIV applet version
     *
     * @return firmware version
     */
    public Version getVersion() {
        return version;
    }

    /**
     * Resets the application to just-installed state.
     *
     * @throws IOException in case of connection error
     */
    public void reset() throws IOException, ApduException {
        blockPin();
        blockPuk();
        sendAndReceive(new Apdu(0, INS_RESET, 0, 0, null));
    }

    /**
     * Authenticate with management key
     *
     * @param managementKey management key as byte array
     *                      The default 3DES management key (9B) is 010203040506070801020304050607080102030405060708.
     * @throws IOException in case of connection error
     */
    public void authenticate(byte[] managementKey) throws IOException, ApduException, BadResponseException {
        // An empty witness is a request for a witness.
        byte[] request = new Tlv(TAG_DYN_AUTH, new Tlv(TAG_AUTH_WITNESS, null).getBytes()).getBytes();
        byte[] response = sendAndReceive(new Apdu(0, INS_AUTHENTICATE, TDES, Slot.CARD_MANAGEMENT.value, request));

        // Witness (tag '80') contains encrypted data (unrevealed fact).
        byte[] witness = TlvUtils.unwrapTlv(TlvUtils.unwrapTlv(response, TAG_DYN_AUTH), TAG_AUTH_WITNESS);
        SecretKey key = new SecretKeySpec(managementKey, "DESede");
        try {
            List<Tlv> dataTlv = new ArrayList<>();
            // This decrypted witness
            dataTlv.add(new Tlv(TAG_AUTH_WITNESS, CryptoUtils.decryptDESede(key, witness)));
            //  The challenge (tag '81') contains clear data (byte sequence),
            byte[] challenge = generateChallenge();
            dataTlv.add(new Tlv(TAG_AUTH_CHALLENGE, challenge));

            request = new Tlv(TAG_DYN_AUTH, TlvUtils.packTlvList(dataTlv)).getBytes();
            response = sendAndReceive(new Apdu(0, INS_AUTHENTICATE, TDES, Slot.CARD_MANAGEMENT.value, request));

            // (tag '82') contains either the decrypted data from tag '80' or the encrypted data from tag '81'.
            byte[] encryptedData = TlvUtils.unwrapTlv(TlvUtils.unwrapTlv(response, TAG_DYN_AUTH), TAG_AUTH_RESPONSE);
            byte[] expectedData = CryptoUtils.encryptDESede(key, challenge);
            if (!Arrays.equals(encryptedData, expectedData)) {
                Logger.d(String.format(Locale.ROOT, "Expected response: %s and Actual response %s",
                        StringUtils.bytesToHex(expectedData),
                        StringUtils.bytesToHex(encryptedData)));
                throw new BadResponseException("Calculated response for challenge is incorrect");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException e) {
            //This should never happen
            throw new RuntimeException(e);
        }
    }

    /**
     * Sign message with private key on YubiKey
     * This method requires verification with pin {@link PivApplication#verify(String)}}
     *
     * @param slot      slot on the YubiKey that stores private key
     * @param algorithm which algorithm is used for signing {@link Algorithm}
     * @param message   the message that needs to be signed
     * @return signature
     * @throws IOException in case of connection error
     */
    public byte[] sign(Slot slot, Algorithm algorithm, byte[] message) throws IOException, ApduException {
        byte[] hash;
        try {
            hash = getMessageHash(message);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedEncodingException(e.getMessage());
        }

        byte[] requestMessage;
        if (algorithm == Algorithm.RSA1024 || algorithm == Algorithm.RSA2048) {
            requestMessage = addPkcs1_15Padding(algorithm == Algorithm.RSA1024 ? 128 : 256, hash);
        } else {
            requestMessage = hash;
        }

        boolean lengthCondition;
        switch (algorithm) {
            case RSA1024:
                lengthCondition = requestMessage.length == 128;
                break;
            case RSA2048:
                lengthCondition = requestMessage.length == 256;
                break;
            case ECCP256:
                lengthCondition = requestMessage.length <= 32;
                break;
            case ECCP384:
                lengthCondition = requestMessage.length <= 48;
                break;
            default:
                throw new UnsupportedEncodingException("Not supported algorithm " + algorithm.name());
        }
        if (!lengthCondition) {
            throw new UnsupportedEncodingException("Input has invalid length " + requestMessage.length + " for algorithm " + algorithm.name());
        }

        // using generic authentication for sign requests
        List<Tlv> dataTlv = new ArrayList<>();
        dataTlv.add(new Tlv(TAG_AUTH_RESPONSE, null));
        dataTlv.add(new Tlv(TAG_AUTH_CHALLENGE, requestMessage));
        byte[] request = new Tlv(TAG_DYN_AUTH, TlvUtils.packTlvList(dataTlv)).getBytes();

        try {
            byte[] response = sendAndReceive(new Apdu(0, INS_AUTHENTICATE, algorithm.value, slot.value, request));
            return new Tlv(new Tlv(response, 0).getValue(), 0).getValue();
        } catch (ApduException e) {
            if (INCORRECT_VALUES_ERROR == e.getStatusCode()) {
                throw new ApduException(e.getApdu(), String.format(Locale.ROOT, "Make sure that %s key is generated on slot %02X", algorithm.name(), slot.value));
            }
            throw e;
        }
    }

    /**
     * Change management key
     * This method requires authentication {@link PivApplication#authenticate(byte[])}
     *
     * @param managementKey new value of management key
     * @throws IOException in case of connection error
     */
    public void setManagementKey(byte[] managementKey) throws IOException, ApduException {
        if (managementKey.length != 24) {
            throw new IllegalArgumentException("Management key must be 24 bytes");
        }

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(TDES);
        stream.write(new Tlv(Slot.CARD_MANAGEMENT.value, managementKey).getBytes());

        // NOTE: if p2=0xfe key requires touch
        // Require touch is only available on YubiKey 4 & 5.
        sendAndReceive(new Apdu(0, INS_SET_MGMKEY, 0xff, 0xff, stream.toByteArray()));
    }

    /**
     * Authenticate with pin
     * Verify without PIN gives number of tries left without using this attempts
     * 0  - PIN authentication blocked.
     * Note: that 15 is the highest value that will be returned even if remaining tries is higher.
     *
     * @param pin string with pin (UTF-8), can be null for getting number of attempts only
     *            The default PIN code is 123456.
     * @throws IOException         in case of connection error
     * @throws InvalidPinException in case if pin is invalid
     */
    public void verify(String pin) throws IOException, ApduException, BadRequestException, InvalidPinException {
        try {
            sendAndReceive(new Apdu(0, INS_VERIFY, 0, PIN_P2, pin != null ? pinBytes(pin) : null));
        } catch (ApduException e) {
            int retries = getRetriesFromCode(e.getStatusCode());
            if (retries >= 0) {
                throw new InvalidPinException(retries);
            } else {
                // status code returned error, not number of retries
                throw e;
            }
        }
    }

    /**
     * Receive number of attempts left for PIN from YubiKey
     *
     * @return number of attempts left
     * @throws IOException in case of connection error
     */
    public int getPinAttempts() throws IOException, ApduException {
        try {
            verify(null);
            throw new IllegalStateException("Verification with null pin never returns success status");
        } catch (InvalidPinException e) {
            return e.getRetryCounter();
        } catch (BadRequestException e) {
            throw new RuntimeException(e);  //This shouldn't happen
        }
    }

    /**
     * Change pin
     *
     * @param oldPin old pin for verification
     * @param newPin new pin to set
     * @throws IOException         in case of connection error
     * @throws InvalidPinException in case if pin is invalid
     */
    public void changePin(String oldPin, String newPin) throws IOException, ApduException, InvalidPinException, BadRequestException {
        changeReference(INS_CHANGE_REFERENCE, PIN_P2, oldPin, newPin);
    }

    /**
     * Change puk
     *
     * @param oldPuk old puk for verification
     * @param newPuk new puk to set
     * @throws IOException         in case of connection error
     * @throws InvalidPinException in case if puk is invalid
     */
    public void changePuk(String oldPuk, String newPuk) throws IOException, ApduException, BadRequestException, InvalidPinException {
        changeReference(INS_CHANGE_REFERENCE, PUK_P2, oldPuk, newPuk);
    }

    /**
     * Unblock pin
     *
     * @param puk    puk for verification
     *               The default PUK code is 12345678.
     * @param newPin new pin to set
     * @throws IOException         in case of connection error
     * @throws InvalidPinException in case if puk is invalid
     */
    public void unblockPin(String puk, String newPin) throws IOException, ApduException, BadRequestException, InvalidPinException {
        changeReference(INS_RESET_RETRY, PIN_P2, puk, newPin);
    }

    /**
     * Set pin and puk reties
     * This method requires authentication {@link PivApplication#authenticate(byte[])}
     * and verification with pin {@link PivApplication#verify(String)}}
     *
     * @param pinRetries sets attempts to pin
     * @param pukRetries sets attempts to puk
     * @throws IOException in case of connection error
     */
    public void setPinRetries(int pinRetries, int pukRetries) throws IOException, ApduException {
        sendAndReceive(new Apdu(0, INS_SET_PIN_RETRIES, pinRetries, pukRetries, null));
    }

    /**
     * Reads certificate loaded on slot
     *
     * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
     * @return certificate instance
     * @throws IOException in case of connection error
     */
    public X509Certificate getCertificate(Slot slot) throws IOException, ApduException, BadResponseException {
        byte[] objectData = getObject(slot.object);

        SparseArray<byte[]> certData = TlvUtils.parseTlvMap(objectData);
        byte[] certInfo = certData.get(TAG_CERT_INFO);
        if (certInfo != null && certInfo.length > 0 && certInfo[0] != 0) {
            throw new BadResponseException("Compressed certificates are not supported");
        }

        try {
            return parseCertificate(certData.get(TAG_CERTIFICATE));
        } catch (CertificateException e) {
            throw new BadResponseException("Failed to parse certificate: ", e);
        }
    }

    /**
     * Import certificate instance to YubiKey
     * This method requires authentication {@link PivApplication#authenticate(byte[])}
     *
     * @param slot        Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
     * @param certificate certificate instance
     * @throws IOException in case of connection error
     */
    public void putCertificate(Slot slot, X509Certificate certificate) throws IOException, ApduException {
        byte[] certBytes;
        try {
            certBytes = certificate.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new IllegalArgumentException("Failed to get encoded version of certificate", e);
        }
        List<Tlv> requestTlv = new ArrayList<>();
        requestTlv.add(new Tlv(TAG_CERTIFICATE, certBytes));
        requestTlv.add(new Tlv(TAG_CERT_INFO, new byte[]{0}));
        requestTlv.add(new Tlv(TAG_LRC, null));
        putObject(slot.object, TlvUtils.packTlvList(requestTlv));
    }

    /**
     * This feature is only available in YubiKey 4.3 and newer.
     * A high level description of the thinking and how this can be used can be found at
     * https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
     * Attestation works through a special key slot called "f9" this comes pre-loaded from factory with a key and cert signed by Yubico,
     * but can be overwritten. After a key has been generated in a normal slot it can be attested by this special key
     * <p>
     * This method requires authentication {@link PivApplication#authenticate(byte[])}
     * This method requires key to be generated on slot {@link PivApplication#generateKey(Slot, Algorithm, PinPolicy, TouchPolicy)}
     *
     * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
     * @return X.509 certificate for the key that is to be attested
     * @throws IOException in case of connection error
     */
    public X509Certificate attest(Slot slot) throws IOException, YubiKeyCommunicationException {
        if (version.isLessThan(4, 3, 0)) {
            throw new NotSupportedOperation("This operation is supported for version 4.3+");
        }
        try {
            byte[] responseData = sendAndReceive(new Apdu(0, INS_ATTEST, slot.value, 0, null));
            return parseCertificate(responseData);
        } catch (ApduException e) {
            if (INCORRECT_VALUES_ERROR == e.getStatusCode()) {
                throw new ApduException(e.getApdu(), String.format(Locale.ROOT, "Make sure that key is generated on slot %02X", slot.value));
            }
            throw e;
        } catch (CertificateException e) {
            throw new BadResponseException("Failed to parse certificate", e);
        }
    }

    /**
     * Deletes certificate from YubiKey
     * This method requires authentication {@link PivApplication#authenticate(byte[])}
     *
     * @param slot Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
     * @throws IOException in case of connection error
     */
    public void deleteCertificate(Slot slot) throws IOException, ApduException {
        putObject(slot.object, null);
    }

    /**
     * Generate public key (for example for Certificate Signing Request)
     * This method requires verification with pin {@link PivApplication#verify(String)}}
     * and authentication with management key {@link PivApplication#authenticate(byte[])}
     *
     * @param slot        Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
     * @param algorithm   which algorithm is used for key generation {@link Algorithm}
     * @param pinPolicy   pin policy {@link PinPolicy}
     * @param touchPolicy touch policy {@link TouchPolicy}
     * @return public key for generated pair
     * @throws IOException in case of connection error
     */
    public PublicKey generateKey(Slot slot, Algorithm algorithm, PinPolicy pinPolicy, TouchPolicy touchPolicy) throws IOException, ApduException, BadResponseException {
        if (!SUPPORTED_ALGORITHMS.contains(algorithm)) {
            throw new IllegalArgumentException(String.format(Locale.ROOT, "Unsupported algorithm: 0x%02x", algorithm.value));
        }
        boolean isRsa = algorithm == Algorithm.RSA1024 || algorithm == Algorithm.RSA2048;

        if (isRsa && version.isAtLeast(4, 2, 0) && version.isLessThan(4, 3, 5)) {
            throw new UnsupportedOperationException("RSA key generation is not supported on this YubiKey");
        }
        if (version.isLessThan(4, 0, 0)) {
            if (algorithm == Algorithm.ECCP384) {
                throw new UnsupportedOperationException("Elliptic curve P384 is not supported on this YubiKey");
            }
            if (touchPolicy != TouchPolicy.DEFAULT || pinPolicy != PinPolicy.DEFAULT) {
                throw new UnsupportedOperationException("PIN/Touch policy is not supported on this YubiKey");
            }
        }
        if (touchPolicy == TouchPolicy.CACHED && version.isLessThan(4, 3, 0)) {
            throw new UnsupportedOperationException("Cached touch policy is not supported on this YubiKey");
        }

        List<Tlv> tlvs = new ArrayList<>();
        tlvs.add(new Tlv(TAG_GEN_ALGORITHM, new byte[]{(byte) algorithm.value}));
        if (pinPolicy != PinPolicy.DEFAULT) {
            tlvs.add(new Tlv(TAG_PIN_POLICY, new byte[]{(byte) pinPolicy.value}));
        }
        if (touchPolicy != TouchPolicy.DEFAULT) {
            tlvs.add(new Tlv(TAG_TOUCH_POLICY, new byte[]{(byte) touchPolicy.value}));
        }

        byte[] response = sendAndReceive(new Apdu(0, INS_GENERATE_ASYMMETRIC, 0, slot.value, new Tlv((byte) 0xac, TlvUtils.packTlvList(tlvs)).getBytes()));

        // Tag '7F49' contains data objects for RSA or ECC
        SparseArray<byte[]> dataObjects = TlvUtils.parseTlvMap(TlvUtils.unwrapTlv(response, 0x7F49));

        try {
            if (isRsa) {
                BigInteger modulus = new BigInteger(1, dataObjects.get(0x81));
                BigInteger exponent = new BigInteger(1, dataObjects.get(0x82));
                return publicRsaKey(modulus, exponent);
            } else {
                byte[] encoded = dataObjects.get(0x86);
                return publicEccKey(algorithm == Algorithm.ECCP256 ? CryptoUtils.Curve.P256 : CryptoUtils.Curve.P384, encoded);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e); // This shouldn't happen
        }
    }

    /**
     * Import private key to YubiKey
     * This method requires authentication {@link PivApplication#authenticate(byte[])}
     *
     * @param slot        Key reference '9A', '9C', '9D', or '9E'. {@link Slot}.
     * @param key         private key to import
     * @param pinPolicy   pin policy {@link PinPolicy}
     * @param touchPolicy touch policy {@link TouchPolicy}
     * @return type of algorithm that was parsed from key
     * @throws IOException in case of connection error
     */
    public Algorithm importKey(Slot slot, PrivateKey key, PinPolicy pinPolicy, TouchPolicy touchPolicy) throws IOException, ApduException {
        Algorithm algorithm;
        List<Tlv> tlvs = new ArrayList<>();
        if (!"PKCS#8".equals(key.getFormat())) {
            throw new UnsupportedEncodingException("Unsupported private key encoding");
        }

        if ("RSA".equals(key.getAlgorithm())) {
            RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) key;
            int length;
            switch (rsaPrivateKey.getModulus().bitLength()) {
                case 1024:
                    algorithm = Algorithm.RSA1024;
                    length = 64;
                    break;
                case 2048:
                    algorithm = Algorithm.RSA2048;
                    length = 128;
                    break;
                default:
                    throw new UnsupportedEncodingException("Unsupported RSA key size = " + rsaPrivateKey.getModulus().bitLength());
            }

            if (rsaPrivateKey.getPublicExponent().intValue() != 65537) {
                throw new UnsupportedEncodingException("Unsupported RSA public exponent");
            }

            tlvs.add(new Tlv((byte) 0x01, bytesToLength(rsaPrivateKey.getPrimeP(), length)));         // p
            tlvs.add(new Tlv((byte) 0x02, bytesToLength(rsaPrivateKey.getPrimeQ(), length)));         // q
            tlvs.add(new Tlv((byte) 0x03, bytesToLength(rsaPrivateKey.getPrimeExponentP(), length)));      // dmp1
            tlvs.add(new Tlv((byte) 0x04, bytesToLength(rsaPrivateKey.getPrimeExponentQ(), length)));      // dmq1
            tlvs.add(new Tlv((byte) 0x05, bytesToLength(rsaPrivateKey.getCrtCoefficient(), length)));    // iqmp
        } else if ("EC".equals(key.getAlgorithm())) {
            ECPrivateKey ecPrivateKey = (ECPrivateKey) key;
            int length;
            switch (ecPrivateKey.getParams().getCurve().getField().getFieldSize()) {
                case 256:
                    algorithm = Algorithm.ECCP256;
                    length = 32;
                    break;
                case 384:
                    algorithm = Algorithm.ECCP384;
                    length = 48;
                    break;
                default:
                    throw new UnsupportedEncodingException("Unsupported curve");
            }
            tlvs.add(new Tlv((byte) 0x06, bytesToLength(ecPrivateKey.getS(), length)));  // s
        } else {
            throw new UnsupportedEncodingException("Unsupported private key algorithm");
        }

        if (pinPolicy != PinPolicy.DEFAULT) {
            tlvs.add(new Tlv(TAG_PIN_POLICY, new byte[]{(byte) pinPolicy.value}));
        }
        if (touchPolicy != TouchPolicy.DEFAULT) {
            tlvs.add(new Tlv(TAG_TOUCH_POLICY, new byte[]{(byte) touchPolicy.value}));
        }

        sendAndReceive(new Apdu(0, INS_IMPORT_KEY, algorithm.value, slot.value, TlvUtils.packTlvList(tlvs)));
        return algorithm;
    }

    /**
     * Read object data from YubiKey
     *
     * @param objectId slot/data type to read
     *                 Values of objectId data for slots {@link Slot#object} and other:
     *                 CAPABILITY = 0x5fc107
     *                 CHUID = 0x5fc102
     *                 FINGERPRINTS = 0x5fc103
     *                 SECURITY = 0x5fc106
     *                 FACIAL = 0x5fc108
     *                 DISCOVERY = 0x7e
     *                 KEY_HISTORY = 0x5fc10c
     *                 IRIS = 0x5fc121
     * @return data that read from YubiKey
     * @throws IOException in case of connection error
     */
    public byte[] getObject(byte[] objectId) throws IOException, ApduException, UnexpectedTagException {
        byte[] requestData = new Tlv(TAG_OBJ_ID, objectId).getBytes();
        byte[] responseData = sendAndReceive(new Apdu(0, INS_GET_DATA, 0x3f, 0xff, requestData));
        return TlvUtils.unwrapTlv(responseData, TAG_OBJ_DATA);
    }

    /**
     * Put object data to YubiKey
     *
     * @param objectId   slot/data type to put
     *                   Values of objectId data for slots {@link Slot#object} and other:
     *                   CAPABILITY = 0x5fc107
     *                   CHUID = 0x5fc102
     *                   FINGERPRINTS = 0x5fc103
     *                   SECURITY = 0x5fc106
     *                   FACIAL = 0x5fc108
     *                   DISCOVERY = 0x7e
     *                   KEY_HISTORY = 0x5fc10c
     *                   IRIS = 0x5fc121
     * @param objectData data to write
     * @throws IOException in case of connection error
     */
    public void putObject(byte[] objectId, byte[] objectData) throws IOException, ApduException {
        List<Tlv> requestTlv = new ArrayList<>();
        requestTlv.add(new Tlv(TAG_OBJ_ID, objectId));
        requestTlv.add(new Tlv(TAG_OBJ_DATA, objectData));
        sendAndReceive(new Apdu(0, INS_PUT_DATA, 0x3f, 0xff, TlvUtils.packTlvList(requestTlv)));
    }

    /**
     * Calculate message SHA256
     *
     * @param message the message
     * @return hash of the input message
     * @throws NoSuchAlgorithmException
     */
    private byte[] getMessageHash(byte[] message) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
        messageDigest.update(message);
        return messageDigest.digest();

    }

    /**
     * Adding padding and prefix to hash message
     *
     * @param length required length of hash message specific to algorithm
     * @param hash   hash of message
     * @return padded hash message to requested length
     * @throws IOException never occurs because we do only memory stream writing
     */
    private byte[] addPkcs1_15Padding(int length, byte[] hash) throws IOException {
        int paddingLength = length - (RSA_HASH_SHA256_PREFIX.length + hash.length) - 3;
        ByteArrayOutputStream stream = new ByteArrayOutputStream();

        // pkcs1 BT01 padding
        stream.write(new byte[]{0x00, 0x01});
        // Fill padding with 0xff.
        // The same with
        // byte[] padding = new byte[paddingLength];
        // Arrays.fill(padding, (byte)0xff);
        // stream,write(padding)
        while (paddingLength-- > 0) {
            stream.write((byte) 0xff);
        }
        stream.write(0x00);
        stream.write(RSA_HASH_SHA256_PREFIX);
        stream.write(hash);
        return stream.toByteArray();
    }

    /**
     * Generates x509 certificate object from byte array
     *
     * @param data contains certificate data
     * @return java.security.cert.X509Certificate representation of certificate
     * @throws CertificateException
     */
    private X509Certificate parseCertificate(byte[] data) throws CertificateException {
        InputStream stream = new ByteArrayInputStream(data);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(stream);
    }

    /**
     * Doing data formatting/padding to provided length (shortens to length or fills with 0 rest of array)
     *
     * @param value  data to be padded
     * @param length length of new array
     * @return array of bytes sized by provided length
     */
    private static byte[] bytesToLength(BigInteger value, int length) {
        byte[] data = value.toByteArray();
        Logger.d("Changing byte array from " + data.length + " to " + length);
        if (data.length == length) {
            return data;
        } else if (data.length > length) {
            return Arrays.copyOfRange(data, data.length - length, data.length);
        } else {
            byte[] padded = new byte[length];
            System.arraycopy(data, 0, padded, length - data.length, data.length);
            return padded;
        }
    }

    private void changeReference(byte instruction, byte p2, @Nullable String value1, @Nullable String value2) throws IOException, ApduException, BadRequestException, InvalidPinException {
        byte[] pinBytes = pinBytes(value1 != null ? value1 : "", value2 != null ? value2 : "");
        try {
            sendAndReceive(new Apdu(0, instruction, 0, p2, pinBytes));
        } catch (ApduException e) {
            int retries = getRetriesFromCode(e.getStatusCode());
            if (retries >= 0) {
                throw new InvalidPinException(retries);
            } else {
                throw e;
            }
        }
    }

    private void blockPin() throws IOException, ApduException {
        // Note: that 15 is the highest value that will be returned even if remaining tries is higher.
        int counter = getPinAttempts();
        while (counter > 0) {
            try {
                verify("");
            } catch (InvalidPinException e) {
                counter = e.getRetryCounter();
            } catch (BadRequestException e) {
                throw new RuntimeException(e);  // This shouldn't happen
            }
        }

        Logger.d("PIN is blocked");
    }

    private void blockPuk() throws IOException, ApduException {
        // A failed unblock pin will return number of PUK tries left and also uses one try.
        int counter = 1;
        while (counter > 0) {
            try {
                unblockPin(null, null);
            } catch (InvalidPinException e) {
                counter = e.getRetryCounter();
            } catch (BadRequestException e) {
                throw new RuntimeException(e);  // This shouldn't happen
            }
        }
        Logger.d("PUK is blocked");
    }

    private static byte[] pinBytes(String pin) throws BadRequestException {
        byte[] pinBytes = pin.getBytes(StandardCharsets.UTF_8);
        if (pinBytes.length > PIN_SIZE) {
            throw new BadRequestException("PIN/PUK must be no longer than 8 bytes");
        }

        byte[] alignedPinByte = Arrays.copyOf(pinBytes, PIN_SIZE);
        Arrays.fill(alignedPinByte, pin.length(), PIN_SIZE, (byte) 0xff);
        return alignedPinByte;
    }

    private static byte[] pinBytes(String pin1, String pin2) throws IOException, BadRequestException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(pinBytes(pin1));
        stream.write(pinBytes(pin2));
        return stream.toByteArray();
    }

    /**
     * Parses number of left attempts from status code
     *
     * @param statusCode received within response from YubiKey
     * @return number of retries
     */
    private int getRetriesFromCode(int statusCode) {
        if (statusCode == AUTH_METHOD_BLOCKED) {
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

    /**
     * Generated random 8 bytes that can be used as challenge for authentication
     *
     * @return random 8 bytes
     */
    private static byte[] generateChallenge() {
        byte[] challenge = new byte[8];
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                SecureRandom.getInstanceStrong().nextBytes(challenge);
            } catch (NoSuchAlgorithmException e) {
                new SecureRandom().nextBytes(challenge);
            }
        } else {
            new SecureRandom().nextBytes(challenge);
        }
        return challenge;
    }
}

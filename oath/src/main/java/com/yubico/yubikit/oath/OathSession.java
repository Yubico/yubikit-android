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

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.ApplicationSession;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.application.Feature;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.annotation.Nullable;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Communicates with a YubiKey's OATH application.
 * https://developers.yubico.com/OATH/YKOATH_Protocol.html
 */
public class OathSession extends ApplicationSession<OathSession> {
    // Features
    /**
     * Support for credentials that require touch to use.
     */
    public static final Feature<OathSession> FEATURE_TOUCH = new Feature.Versioned<>("Touch", 4, 2, 0);
    /**
     * Support for credentials using the SHA-512 hash algorithm.
     */
    public static final Feature<OathSession> FEATURE_SHA512 = new Feature.Versioned<>("SHA-512", 4, 3, 1);
    /**
     * Support for renaming a stored credential.
     */
    public static final Feature<OathSession> FEATURE_RENAME = new Feature.Versioned<>("Rename Credential", 5, 3, 0);

    // Tlv tags for credential data
    private static final int TAG_NAME = 0x71;
    private static final int TAG_KEY = 0x73;
    private static final int TAG_RESPONSE = 0x75;
    private static final int TAG_PROPERTY = 0x78;
    private static final int TAG_IMF = 0x7a;
    private static final int TAG_CHALLENGE = 0x74;

    // Instruction bytes for APDU commands
    private static final byte INS_LIST = (byte) 0xa1;
    private static final byte INS_PUT = 0x01;
    private static final byte INS_DELETE = 0x02;
    private static final byte INS_SET_CODE = 0x03;
    private static final byte INS_RESET = 0x04;
    private static final byte INS_RENAME = 0x05;
    private static final byte INS_CALCULATE = (byte) 0xa2;
    private static final byte INS_VALIDATE = (byte) 0xa3;
    private static final byte INS_CALCULATE_ALL = (byte) 0xa4;
    private static final byte INS_SEND_REMAINING = (byte) 0xa5;

    private static final byte PROPERTY_REQUIRE_TOUCH = (byte) 0x02;

    private static final byte[] AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01};

    private static final long MILLS_IN_SECOND = 1000;
    private static final int DEFAULT_PERIOD = 30;
    private static final int CHALLENGE_LEN = 8;
    private static final int ACCESS_KEY_LEN = 16;

    private final SmartCardProtocol protocol;

    /**
     * Version, ID and a challenge if authentication is configured
     */
    private final OathApplicationInfo applicationInfo;


    /**
     * Create new instance of {@link OathSession}
     * and selects the application for use
     *
     * @param connection to the YubiKey
     * @throws IOException                      in case of connection error
     * @throws ApplicationNotAvailableException if the application is missing or disabled
     */
    public OathSession(SmartCardConnection connection) throws IOException, ApplicationNotAvailableException {
        protocol = new SmartCardProtocol(connection, INS_SEND_REMAINING);
        applicationInfo = new OathApplicationInfo(protocol.select(AID));
        protocol.enableTouchWorkaround(applicationInfo.getVersion());
    }

    @Override
    public void close() throws IOException {
        protocol.close();
    }

    @Override
    public Version getVersion() {
        return applicationInfo.getVersion();
    }

    /**
     * @return version, ID and a challenge if authentication is configured
     */
    public OathApplicationInfo getApplicationInfo() {
        return applicationInfo;
    }

    /**
     * Resets the application, deleting all credentials and removing any lock code.
     *
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public void reset() throws IOException, ApduException {
        protocol.sendAndReceive(new Apdu(0, INS_RESET, 0xde, 0xad, null));
    }

    /**
     * Validates authentication (mutually).
     * The challenge for this comes from the SELECT command.
     * The response if computed by performing the correct HMAC function of that challenge with the correct key.
     * A new challenge is then sent to the application, together with the response.
     * The application will then respond with a similar calculation that the host software can verify.
     *
     * @param password user-supplied password
     * @return true if password valid
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public boolean validate(char[] password) throws IOException, ApduException {
        if (applicationInfo.isAuthenticationRequired() && (password.length == 0)) {
            return false;
        }

        try {
            byte[] secret = deriveAccessKey(password, applicationInfo.getSalt());
            try {
                return validate(challenge -> doHmacSha1(secret, challenge));
            } finally {
                Arrays.fill(secret, (byte) 0);
            }
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e); // This shouldn't happen.
        }
    }

    /**
     * Validates authentication (mutually).
     * The challenge for this comes from the SELECT command.
     * The response if computed by performing the correct HMAC function of that challenge with the correct key.
     * A new challenge is then sent to the application, together with the response.
     * The application will then respond with a similar calculation that the host software can verify.
     *
     * @param signer the provide of HMAC calculation
     * @return if the command was successful or not
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public boolean validate(ChallengeSigner signer) throws IOException, ApduException {
        byte[] challenge = applicationInfo.getChallenge();
        // if no validation/authentication required we consider that validation was successful
        if (challenge == null) {
            return true;
        }

        try {
            Map<Integer, byte[]> request = new LinkedHashMap<>();
            request.put(TAG_RESPONSE, signer.sign(challenge));

            byte[] clientChallenge = RandomUtils.getRandomBytes(CHALLENGE_LEN);
            request.put(TAG_CHALLENGE, clientChallenge);

            byte[] data = protocol.sendAndReceive(new Apdu(0, INS_VALIDATE, 0, 0, Tlvs.encodeMap(request)));
            Map<Integer, byte[]> map = Tlvs.decodeMap(data);
            // return false if response from validation does not match verification
            return (Arrays.equals(signer.sign(clientChallenge), map.get(TAG_RESPONSE)));
        } catch (ApduException e) {
            if (e.getSw() == SW.INCORRECT_PARAMETERS) {
                // key didn't recognize secret
                return false;
            }
            throw e;
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e); // This shouldn't happen
        }

    }

    /**
     * Sets an access key derived from a password. Once an access key is set, any usage of the credentials stored will
     * require the application to be unlocked via one of the validate methods. Also see {@link #setAccessKey(byte[])}.
     *
     * @param password user-supplied password to set, encoded as UTF-8 bytes
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public void setPassword(char[] password) throws IOException, ApduException {
        try {
            setAccessKey(deriveAccessKey(password, applicationInfo.getSalt()));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e); // this shouldn't happen.
        }
    }

    /**
     * Sets an access key. Once an access key is set, any usage of the credentials stored will require the application
     * to be unlocked via one of the validate methods, which requires knowledge of the access key. Typically this key is
     * derived from a password (see {@link #deriveAccessKey(char[], byte[])}) and is set by instead using the
     * {@link #setPassword(char[])} method. This method sets the raw 16 byte key.
     *
     * @param key the shared secret key used to unlock access to the application
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public void setAccessKey(byte[] key) throws IOException, ApduException {
        if (key.length != ACCESS_KEY_LEN) {
            throw new IllegalArgumentException("Secret should be 16 bytes");
        }

        Map<Integer, byte[]> request = new LinkedHashMap<>();
        request.put(TAG_KEY, ByteBuffer.allocate(1 + key.length)
                .put((byte) (OathType.TOTP.value | HashAlgorithm.SHA1.value))
                .put(key)
                .array());

        byte[] challenge = RandomUtils.getRandomBytes(CHALLENGE_LEN);
        request.put(TAG_CHALLENGE, challenge);
        try {
            request.put(TAG_RESPONSE, doHmacSha1(key, challenge));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e); //This shouldn't happen
        }

        protocol.sendAndReceive(new Apdu(0, INS_SET_CODE, 0, 0, Tlvs.encodeMap(request)));
    }

    /**
     * Removes the access key, if one is set.
     *
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public void deleteAccessKey() throws IOException, ApduException {
        protocol.sendAndReceive(new Apdu(0, INS_SET_CODE, 0, 0, new Tlv(TAG_KEY, null).getBytes()));
    }

    /**
     * Lists configured credentials.
     *
     * @return list of credentials on device
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public List<Credential> getCredentials() throws IOException, ApduException {
        byte[] response = protocol.sendAndReceive(new Apdu(0, INS_LIST, 0, 0, null));
        List<Tlv> list = Tlvs.decodeList(response);
        List<Credential> result = new ArrayList<>();
        for (Tlv tlv : list) {
            result.add(new Credential(applicationInfo.getDeviceId(), new ListResponse(tlv)));
        }
        return result;
    }

    /**
     * Performs CALCULATE for all available credentials.
     *
     * @return returns credential + response for TOTP and just credential with null code for HOTP and credentials requiring touch.
     * @throws IOException          in case of connection error
     * @throws ApduException        in case of communication error
     * @throws BadResponseException in case of incorrect YubiKey response
     */
    public Map<Credential, Code> calculateCodes() throws IOException, ApduException, BadResponseException {
        return calculateCodes(System.currentTimeMillis());
    }

    /**
     * Performs CALCULATE for all available credentials.
     *
     * @param timestamp the timestamp which is used as start point for TOTP
     * @return returns credential + response for TOTP and just credential for HOTP and credentials requiring touch.
     * @throws IOException          in case of connection error
     * @throws ApduException        in case of communication error
     * @throws BadResponseException in case of incorrect YubiKey response
     */
    public Map<Credential, Code> calculateCodes(long timestamp) throws IOException, ApduException, BadResponseException {
        long timeStep = (timestamp / MILLS_IN_SECOND / DEFAULT_PERIOD);
        byte[] challenge = ByteBuffer.allocate(CHALLENGE_LEN).putLong(timeStep).array();

        // using default period to 30 second for all _credentials and then recalculate those that have different period
        byte[] data = protocol.sendAndReceive(new Apdu(0, INS_CALCULATE_ALL, 0, 1, new Tlv(TAG_CHALLENGE, challenge).getBytes()));
        Iterator<Tlv> responseTlvs = Tlvs.decodeList(data).iterator();
        Map<Credential, Code> map = new HashMap<>();
        while (responseTlvs.hasNext()) {
            Tlv nameTlv = responseTlvs.next();
            if (nameTlv.getTag() != TAG_NAME) {
                throw new BadResponseException(String.format("Unexpected tag: %02x", nameTlv.getTag()));
            }
            byte[] credentialId = nameTlv.getValue();
            CalculateResponse response = new CalculateResponse(responseTlvs.next());

            // parse credential properties
            Credential credential = new Credential(applicationInfo.getDeviceId(), credentialId, response);

            if (credential.getOathType() == OathType.TOTP && credential.getPeriod() != DEFAULT_PERIOD) {
                // recalculate credentials that have different period
                map.put(credential, calculateCode(credential, timestamp));
            } else if (response.response.length == 4) {
                // Note: codes are typically valid in 'DEFAULT_PERIOD' second slices
                // so the valid period actually starts before the calculation happens
                // and potentially might happen even way before (so that code is valid only 1 second after calculation)
                long validFrom = validFrom(timestamp, DEFAULT_PERIOD);
                map.put(credential, new Code(formatTruncated(response), validFrom, validFrom + DEFAULT_PERIOD * MILLS_IN_SECOND));
            } else {
                map.put(credential, null);
            }
        }

        return map;
    }

    /**
     * Perform a raw non-truncated CALCULATE (HMAC) for a credential using the given challenge.
     *
     * @param credentialId credential ID to identify the credential
     * @param challenge    challenge bytes
     * @return calculated HMAC response
     * @throws IOException          in case of connection error
     * @throws ApduException        in case of communication error
     * @throws BadResponseException in case an unexpected response was sent from the YubiKey
     */
    public byte[] calculateResponse(byte[] credentialId, byte[] challenge) throws IOException, ApduException, BadResponseException {
        Map<Integer, byte[]> request = new LinkedHashMap<>();
        request.put(TAG_NAME, credentialId);
        request.put(TAG_CHALLENGE, challenge);
        byte[] data = protocol.sendAndReceive(new Apdu(0, INS_CALCULATE, 0, 0, Tlvs.encodeMap(request)));
        byte[] response = Tlvs.unpackValue(TAG_RESPONSE, data);
        return Arrays.copyOfRange(response, 1, response.length);
    }

    /**
     * Performs CALCULATE for one named credential.
     *
     * @param credential credential that will get new code
     * @return calculated code
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public Code calculateCode(Credential credential) throws IOException, ApduException {
        return calculateCode(credential, System.currentTimeMillis());
    }

    /**
     * Performs CALCULATE for one named credential.
     *
     * @param credential credential that will get new code
     * @param timestamp  the timestamp which is used as start point for TOTP, can be null for HOTP
     * @return calculated code
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public Code calculateCode(Credential credential, @Nullable Long timestamp) throws IOException, ApduException {
        if (!credential.deviceId.equals(applicationInfo.getDeviceId())) {
            throw new IllegalArgumentException("The given credential belongs to a different device!");
        }
        byte[] challenge = new byte[CHALLENGE_LEN];
        if (timestamp != null && credential.getPeriod() != 0) {
            long timeStep = (timestamp / MILLS_IN_SECOND / credential.getPeriod());
            ByteBuffer.wrap(challenge).putLong(timeStep);
        }

        Map<Integer, byte[]> requestTlv = new LinkedHashMap<>();
        requestTlv.put(TAG_NAME, credential.getId());
        requestTlv.put(TAG_CHALLENGE, challenge);
        byte[] data = protocol.sendAndReceive(new Apdu(0, INS_CALCULATE, 0, 1, Tlvs.encodeMap(requestTlv)));
        String value = formatTruncated(new CalculateResponse(Tlv.parse(data)));

        switch (credential.getOathType()) {
            case TOTP:
                long validFrom = validFrom(timestamp, credential.getPeriod());
                return new Code(value, validFrom, validFrom + credential.getPeriod() * MILLS_IN_SECOND);
            case HOTP:
            default:
                return new Code(value, System.currentTimeMillis(), Long.MAX_VALUE);
        }
    }

    /**
     * Adds a new OATH credential.
     * <p>
     * The Credential ID must be unique to the YubiKey, else the existing Credential with the same ID will be overwritten.
     * <p>
     * Setting touchRequired requires support for {@link #FEATURE_TOUCH}, available on YubiKey 4.2 or later.
     * Using SHA-512 requires support for {@link #FEATURE_SHA512}, available on YubiKey 4.3.1 or later.
     *
     * @param credential    credential data to add
     * @param touchRequired true if the credential should require touch to be used
     * @return the newly added Credential
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public Credential putCredential(CredentialData credential, boolean touchRequired) throws IOException, ApduException {
        if (touchRequired) {
            require(FEATURE_TOUCH);
        }
        if (credential.getHashAlgorithm() == HashAlgorithm.SHA512) {
            require(FEATURE_SHA512);
        }

        try {
            byte[] key = credential.getHashAlgorithm().prepareKey(credential.getSecret());
            Map<Integer, byte[]> requestTlvs = new LinkedHashMap<>();
            requestTlvs.put(TAG_NAME, credential.getId());

            requestTlvs.put(TAG_KEY, ByteBuffer.allocate(2 + key.length)
                    .put((byte) (credential.getOathType().value | credential.getHashAlgorithm().value))
                    .put((byte) credential.getDigits())
                    .put(key)
                    .array());

            ByteArrayOutputStream output = new ByteArrayOutputStream();
            output.write(Tlvs.encodeMap(requestTlvs));

            if (touchRequired) {
                output.write(TAG_PROPERTY);
                output.write(PROPERTY_REQUIRE_TOUCH);
            }

            if (credential.getOathType() == OathType.HOTP && credential.getCounter() > 0) {
                output.write(TAG_IMF);
                output.write(4);
                output.write(ByteBuffer.allocate(4).putInt(credential.getCounter()).array());
            }

            protocol.sendAndReceive(new Apdu(0x00, INS_PUT, 0, 0, output.toByteArray()));
            return new Credential(applicationInfo.getDeviceId(), credential, touchRequired);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  //This shouldn't happen
        }
    }

    /**
     * Deletes an existing Credential.
     *
     * @param credentialId ID of the credential to remove
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public void deleteCredential(byte[] credentialId) throws IOException, ApduException {
        protocol.sendAndReceive(new Apdu(0x00, INS_DELETE, 0, 0, new Tlv(TAG_NAME, credentialId).getBytes()));
    }

    /**
     * Deletes an existing Credential.
     *
     * @param credential the Credential to remove
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public void deleteCredential(Credential credential) throws IOException, ApduException {
        if (!credential.deviceId.equals(applicationInfo.getDeviceId())) {
            throw new IllegalArgumentException("The given credential belongs to a different device!");
        }
        deleteCredential(credential.getId());
    }

    /**
     * Change the issuer and name of a credential.
     * <p>
     * This functionality requires support for {@link #FEATURE_RENAME}, available on YubiKey 5.3 or later.
     *
     * @param credentialId ID of the credential to rename
     * @param name         the new name of the credential
     * @param issuer       the new issuer of the credential
     * @return the new credential ID
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public byte[] renameCredential(byte[] credentialId, String name, @Nullable String issuer) throws IOException, ApduException {
        require(FEATURE_RENAME);
        CredentialIdUtils.CredentialIdData data = CredentialIdUtils.parseId(credentialId, OathType.TOTP); // This works for HOTP as well
        byte[] newId = CredentialIdUtils.formatId(issuer, name, OathType.TOTP, data.period);
        protocol.sendAndReceive(new Apdu(0x00, INS_RENAME, 0, 0, Tlvs.encodeList(Arrays.asList(
                new Tlv(TAG_NAME, credentialId),
                new Tlv(TAG_NAME, newId)
        ))));
        return newId;
    }

    /**
     * Change the issuer and name of a credential.
     * <p>
     * This functionality requires support for {@link #FEATURE_RENAME}, available on YubiKey 5.3 or later.
     *
     * @param credential the Credential to rename
     * @param name       the new name of the credential
     * @param issuer     the new issuer of the credential
     * @return the updated Credential
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public Credential renameCredential(Credential credential, String name, @Nullable String issuer) throws IOException, ApduException {
        if (!credential.deviceId.equals(applicationInfo.getDeviceId())) {
            throw new IllegalArgumentException("The given credential belongs to a different device!");
        }
        return new Credential(
                credential.deviceId,
                renameCredential(credential.getId(), name, issuer),
                credential.getIssuer(),
                credential.getName(),
                credential.getOathType(),
                credential.getPeriod(),
                credential.isTouchRequired()
        );
    }

    /**
     * Derives an access key from a password and the device-specific salt.
     * The key is derived by running 1000 rounds of PBKDF2 using the password and salt as inputs, with a 16 byte output.
     *
     * @param password a user-supplied password, encoded as UTF-8 bytes.
     * @param salt     the salt value (retrievable from the OathApplicationInfo object)
     * @return a key for authentication
     * @throws InvalidKeySpecException  in case of crypto operation error
     * @throws NoSuchAlgorithmException in case of crypto operation error
     */
    public static byte[] deriveAccessKey(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec keyspec = new PBEKeySpec(password, salt, 1000, ACCESS_KEY_LEN * 8);
        try {
            return factory.generateSecret(keyspec).getEncoded();
        } finally {
            keyspec.clearPassword();
        }
    }

    /**
     * Calculates an HMAC-SHA1 response
     *
     * @param secret  the secret
     * @param message data in bytes
     * @return the MAC result
     * @throws InvalidKeyException      in case of crypto operation error
     * @throws NoSuchAlgorithmException in case of crypto operation error
     */
    private static byte[] doHmacSha1(byte[] secret, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA1");
        mac.init(new SecretKeySpec(secret, mac.getAlgorithm()));
        return mac.doFinal(message);
    }

    /**
     * Calculate the time when the valid period of code starts
     *
     * @param timestamp current timestamp
     * @param period    period in seconds for how long code is valid from its calculation/generation time
     * @return the start of period when code is valid
     */
    private static long validFrom(@Nullable Long timestamp, int period) {
        if (timestamp == null || period == 0) {
            // handling case to avoid ArithmeticException
            // we can't divide by zero, we can set that it valid from now
            // but its valid period ends the very same time
            return System.currentTimeMillis();
        }

        // Note: codes are valid in 'period' second slices
        // so the valid sliced period actually starts before the calculation happens
        // and potentially might happen even way before
        // (so that code is valid only 1 second after calculation)
        return timestamp - timestamp % (period * MILLS_IN_SECOND);
    }

    /**
     * Truncate result from key to have digits number of code
     *
     * @param data the code received within calculate or calculate all response
     * @return truncated code
     */
    private String formatTruncated(CalculateResponse data) {
        String result = Integer.toString(ByteBuffer.wrap(data.response).getInt());
        String value;
        // truncate result length (align it with value of digits)
        if (result.length() > data.digits) {
            // take last digits
            value = result.substring(result.length() - data.digits);
        } else if (result.length() < data.digits) {
            // or append 0 at the beginning of string
            value = String.format("%" + data.digits + "s", result).replace(' ', '0');
        } else {
            value = result;
        }
        return value;
    }

    static class ListResponse {
        final byte[] id;
        final OathType oathType;
        final HashAlgorithm hashAlgorithm;

        private ListResponse(Tlv tlv) {
            byte[] value = tlv.getValue();
            id = Arrays.copyOfRange(value, 1, value.length);
            oathType = OathType.fromValue((byte) (0xf0 & value[0]));
            hashAlgorithm = HashAlgorithm.fromValue((byte) (0x0f & value[0]));
        }
    }

    static class CalculateResponse {
        final byte responseType;
        final int digits;
        final byte[] response;

        private CalculateResponse(Tlv tlv) {
            responseType = (byte) tlv.getTag();
            byte[] value = tlv.getValue();
            digits = value[0];
            response = Arrays.copyOfRange(value, 1, value.length);
        }
    }
}

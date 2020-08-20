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

import com.yubico.yubikit.exceptions.ApplicationNotAvailableException;
import com.yubico.yubikit.exceptions.NotSupportedOperation;
import com.yubico.yubikit.iso7816.Apdu;
import com.yubico.yubikit.iso7816.ApduException;
import com.yubico.yubikit.iso7816.ApduUtils;
import com.yubico.yubikit.iso7816.Iso7816Application;
import com.yubico.yubikit.iso7816.Iso7816Connection;
import com.yubico.yubikit.utils.RandomUtils;
import com.yubico.yubikit.utils.Tlv;
import com.yubico.yubikit.utils.TlvUtils;

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
public class OathApplication extends Iso7816Application {
    public static final short AUTHENTICATION_REQUIRED_ERROR = 0x6982;
    public static final short WRONG_SYNTAX = 0x6a80;
    public static final short GENERIC_ERROR = 0x6581;
    public static final short NO_SUCH_OBJECT = 0x6984;
    public static final short APPLICATION_NOT_FOUND_ERROR = 0x6a82;

    /**
     * Tlv tags for credential data
     */
    private static final int TAG_NAME = 0x71;
    private static final int TAG_KEY = 0x73;
    private static final int TAG_RESPONSE = 0x75;
    private static final int TAG_PROPERTY = 0x78;
    private static final int TAG_IMF = 0x7a;
    private static final int TAG_CHALLENGE = 0x74;

    /**
     * Instruction bytes for APDU commands
     */
    private static final byte INS_LIST = (byte) 0xa1;
    private static final byte INS_PUT = 0x01;
    private static final byte INS_DELETE = 0x02;
    private static final byte INS_SET_CODE = 0x03;
    private static final byte INS_RESET = 0x04;
    private static final byte INS_CALCULATE = (byte) 0xa2;
    private static final byte INS_VALIDATE = (byte) 0xa3;
    private static final byte INS_CALCULATE_ALL = (byte) 0xa4;
    private static final byte INS_SEND_REMAINING = (byte) 0xa5;

    private static final byte PROPERTY_REQUIRE_TOUCH = (byte) 0x02;

    /**
     * Select OATH application APDU command data (for example for PIV application it's 0xa0, 0x00, 0x00, 0x03, 0x08)
     */
    private static final byte[] AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01};

    private static final long MILLS_IN_SECOND = 1000;
    private static final int DEFAULT_PERIOD = 30;
    private static final int CHALLENGE_LEN = 8;

    /**
     * Version, ID and a challenge if authentication is configured
     */
    private final OathApplicationInfo applicationInfo;


    /**
     * Create new instance of {@link OathApplication}
     * and selects the application for use
     *
     * @param connection to the YubiKey
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public OathApplication(Iso7816Connection connection) throws IOException, ApduException, ApplicationNotAvailableException {
        super(AID, connection);

        applicationInfo = new OathApplicationInfo(select());
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
        sendAndReceive(new Apdu(0, INS_RESET, 0xde, 0xad, null));
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
            byte[] secret = calculateSecret(password, applicationInfo.getSalt());
            return validate(challenge -> calculateResponse(secret, challenge));
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
        // if no validation/authentication required we consider that validation was successful
        if (!applicationInfo.isAuthenticationRequired()) {
            return true;
        }

        try {
            Map<Integer, byte[]> request = new LinkedHashMap<>();
            request.put(TAG_RESPONSE, signer.sign(applicationInfo.getChallenge()));

            byte[] challenge = RandomUtils.getRandomBytes(CHALLENGE_LEN);
            request.put(TAG_CHALLENGE, challenge);

            byte[] data = sendAndReceive(new Apdu(0, INS_VALIDATE, 0, 0, TlvUtils.packTlvMap(request)));
            Map<Integer, byte[]> map = TlvUtils.parseTlvMap(data);
            // return false if response from validation does not match verification
            return (Arrays.equals(signer.sign(challenge), map.get(TAG_RESPONSE)));
        } catch (ApduException e) {
            if (e.getStatusCode() == WRONG_SYNTAX) {
                // key didn't recognize secret
                return false;
            }
            throw e;
        } catch (InvalidKeyException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e); // This shouldn't happen
        }

    }

    /**
     * Configures Authentication.
     *
     * @param password user-supplied password to set
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public void setPassword(char[] password) throws IOException, ApduException {
        try {
            setSecret(calculateSecret(password, applicationInfo.getSalt()));
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e); // this shouldn't happen.
        }
    }

    /**
     * Configures Authentication.
     * The key to be set is expected to be a user-supplied UTF-8 encoded password passed through 1000 rounds of PBKDF2
     * with the ID from select used as salt.
     * 16 bytes of that are used.
     * When configuring authentication you are required to send an 8 byte challenge and
     * one authentication-response with that key, in order to confirm that the application and
     * the host software can calculate the same response for that key.
     *
     * @param secret 16 bytes of user-supplied UTF-8 encoded password passed through 1000 rounds of PBKDF2
     *               with the ID from select used as salt
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public void setSecret(byte[] secret) throws IOException, ApduException {
        if (secret.length != 16) {
            throw new IllegalArgumentException("Secret should be 16 bytes");
        }

        Map<Integer, byte[]> request = new LinkedHashMap<>();
        request.put(TAG_KEY, ByteBuffer.allocate(1 + secret.length)
                .put((byte) (OathType.TOTP.value | HashAlgorithm.SHA1.value))
                .put(secret)
                .array());

        byte[] challenge = RandomUtils.getRandomBytes(CHALLENGE_LEN);
        request.put(TAG_CHALLENGE, challenge);
        try {
            request.put(TAG_RESPONSE, calculateResponse(secret, challenge));
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e); //This shouldn't happen
        }

        sendAndReceive(new Apdu(0, INS_SET_CODE, 0, 0, TlvUtils.packTlvMap(request)));
    }

    /**
     * Removes authentication.
     * If the application is protected with a password, this password is removed.
     *
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public void unsetSecret() throws IOException, ApduException {
        sendAndReceive(new Apdu(0, INS_SET_CODE, 0, 0, new Tlv(TAG_KEY, null).getBytes()));
    }

    /**
     * Lists configured credentials.
     *
     * @return list of credentials on device
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public List<Credential> listCredentials() throws IOException, ApduException {
        byte[] response = sendAndReceive(new Apdu(0, INS_LIST, 0, 0, null));
        List<Tlv> list = TlvUtils.parseTlvList(response);
        List<Credential> result = new ArrayList<>();
        for (Tlv tlv : list) {
            result.add(new Credential(new ListResponse(tlv)));
        }
        return result;
    }

    /**
     * Performs CALCULATE for all available credentials,
     *
     * @return returns credential + response for TOTP and just credential with null code for HOTP and credentials requiring touch.
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public Map<Credential, Code> calculateAll() throws IOException, ApduException {
        return calculateAll(System.currentTimeMillis());
    }

    /**
     * Performs CALCULATE for all available credentials,
     *
     * @param timestamp the timestamp which is used as start point for TOTP
     * @return returns credential + response for TOTP and just credential for HOTP and credentials requiring touch.
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public Map<Credential, Code> calculateAll(long timestamp) throws IOException, ApduException {
        long timeStep = (timestamp / MILLS_IN_SECOND / DEFAULT_PERIOD);
        byte[] challenge = ByteBuffer.allocate(CHALLENGE_LEN).putLong(timeStep).array();

        // using default period to 30 second for all _credentials and then recalculate those that have different period
        byte[] data = sendAndReceive(new Apdu(0, INS_CALCULATE_ALL, 0, 1, new Tlv(TAG_CHALLENGE, challenge).getBytes()));
        Iterator<Tlv> responseTlvs = TlvUtils.parseTlvList(data).iterator();
        Map<Credential, Code> map = new HashMap<>();
        while (responseTlvs.hasNext()) {
            byte[] credentialId = responseTlvs.next().getValue();
            CalculateResponse response = new CalculateResponse(responseTlvs.next());

            // parse credential properties
            Credential credential = new Credential(credentialId, response);

            if (credential.getOathType() == OathType.TOTP && credential.getPeriod() != DEFAULT_PERIOD) {
                // recalculate credentials that have different period
                map.put(credential, calculate(credential, timestamp));
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
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public byte[] calculate(byte[] credentialId, byte[] challenge) throws IOException, ApduException {
        Map<Integer, byte[]> request = new LinkedHashMap<>();
        request.put(TAG_NAME, credentialId);
        request.put(TAG_CHALLENGE, challenge);
        byte[] data = sendAndReceive(new Apdu(0, INS_CALCULATE, 0, 0, TlvUtils.packTlvMap(request)));
        Tlv responseTlv = new Tlv(data, 0);
        return Arrays.copyOfRange(responseTlv.getValue(), 1, responseTlv.getLength());
    }

    /**
     * Performs CALCULATE for one named credential.
     *
     * @param credential credential that will get new code
     * @return calculated code
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public Code calculate(Credential credential) throws IOException, ApduException {
        return calculate(credential, System.currentTimeMillis());
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
    public Code calculate(Credential credential, @Nullable Long timestamp) throws IOException, ApduException {
        byte[] challenge;
        if (timestamp == null || credential.getPeriod() == 0) {
            challenge = new byte[CHALLENGE_LEN];
        } else {
            long timeStep = (timestamp / MILLS_IN_SECOND / credential.getPeriod());
            challenge = ByteBuffer.allocate(CHALLENGE_LEN).putLong(timeStep).array();
        }

        Map<Integer, byte[]> requestTlv = new LinkedHashMap<>();
        requestTlv.put(TAG_NAME, credential.getId());
        requestTlv.put(TAG_CHALLENGE, challenge);
        byte[] data = sendAndReceive(new Apdu(0, INS_CALCULATE, 0, 1, TlvUtils.packTlvMap(requestTlv)));
        Tlv responseTlv = new Tlv(data, 0);
        String value = formatTruncated(new CalculateResponse(responseTlv));

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
     * Adds a new (or overwrites) OATH credential.
     *
     * @param credential credential data to add
     * @return the newly added Credential
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public Credential putCredential(CredentialData credential) throws IOException, ApduException {
        if (credential.isTouchRequired() && applicationInfo.getVersion().isLessThan(4, 0, 0)) {
            throw new NotSupportedOperation("Require touch available on YubiKey 4 or later");
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
            output.write(TlvUtils.packTlvMap(requestTlvs));

            if (credential.isTouchRequired()) {
                output.write(TAG_PROPERTY);
                output.write(PROPERTY_REQUIRE_TOUCH);
            }

            if (credential.getOathType() == OathType.HOTP && credential.getCounter() > 0) {
                output.write(TAG_IMF);
                output.write(4);
                output.write(ByteBuffer.allocate(4).putInt(credential.getCounter()).array());
            }

            Apdu apdu = new Apdu(0x00, INS_PUT, 0, 0, output.toByteArray());
            sendAndReceive(apdu);
            return new Credential(credential);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  //This shouldn't happen
        }
    }

    /**
     * Deletes an existing credential.
     *
     * @param credentialId ID of credential data to remove
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    public void deleteCredential(byte[] credentialId) throws IOException, ApduException {
        Apdu apdu = new Apdu(0x00, INS_DELETE, 0, 0, new Tlv(TAG_NAME, credentialId).getBytes());
        sendAndReceive(apdu);
    }

    /**
     * Passes a user-supplied UTF-8 encoded password through 1000 rounds of PBKDF2
     * with the device ID from select used as salt. 16 bytes of that are used.
     *
     * @param password a user-supplied password
     * @param salt     the salt value (the deviceId returned by select command)
     * @return a secret/key for authentication
     * @throws InvalidKeySpecException  in case of crypto operation error
     * @throws NoSuchAlgorithmException in case of crypto operation error
     */
    public static byte[] calculateSecret(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec keyspec = new PBEKeySpec(password, salt, 1000, 128);
        try {
            return factory.generateSecret(keyspec).getEncoded();
        } finally {
            keyspec.clearPassword();
        }
    }

    /**
     * Calculates HMAC (uses SHA1 as hash function)
     *
     * @param secret  the secret
     * @param message data in bytes
     * @return the MAC result
     * @throws InvalidKeyException      in case of crypto operation error
     * @throws NoSuchAlgorithmException in case of crypto operation error
     */
    private static byte[] calculateResponse(byte[] secret, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA1"); //KeyProperties.KEY_ALGORITHM_HMAC_SHA1 on API 23+
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

    /**
     * Uses ApduUtils.sendAndReceive method with specific ins byte for "send remaining data" command
     *
     * @param command apdu command that will be sent
     * @return data that received from command execution
     * @throws IOException   in case of connection error
     * @throws ApduException in case of communication error
     */
    @Override
    public byte[] sendAndReceive(Apdu command) throws IOException, ApduException {
        //YKOATH uses a non-standard INS for SEND_REMAINING.
        return ApduUtils.sendAndReceive(getConnection(), command, INS_SEND_REMAINING);
    }

    static class ListResponse {
        final byte[] id;
        final OathType oathType;
        final HashAlgorithm hashAlgorithm;

        ListResponse(Tlv tlv) {
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

        CalculateResponse(Tlv tlv) {
            responseType = (byte) tlv.getTag();
            byte[] value = tlv.getValue();
            digits = value[0];
            response = Arrays.copyOfRange(value, 1, value.length);
        }
    }
}

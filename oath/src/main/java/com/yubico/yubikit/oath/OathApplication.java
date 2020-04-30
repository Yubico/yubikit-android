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

import android.os.Build;
import android.text.TextUtils;
import android.util.SparseArray;

import androidx.annotation.Nullable;

import com.yubico.yubikit.Iso7816Application;
import com.yubico.yubikit.apdu.Apdu;
import com.yubico.yubikit.exceptions.ApduException;
import com.yubico.yubikit.apdu.ApduUtils;
import com.yubico.yubikit.apdu.Tlv;
import com.yubico.yubikit.apdu.TlvUtils;
import com.yubico.yubikit.exceptions.ApplicationNotFound;
import com.yubico.yubikit.exceptions.NotSupportedOperation;
import com.yubico.yubikit.transport.YubiKeySession;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Implements all OATH protocol instruction set that Yubikey supports
 * https://developers.yubico.com/OATH/YKOATH_Protocol.html
 */
public class OathApplication  extends Iso7816Application {

    public static final short AUTHENTICATION_REQUIRED_ERROR = 0x6982;
    public static final short WRONG_SYNTAX = 0x6a80;
    public static final short GENERIC_ERROR = 0x6581;
    public static final short NO_SUCH_OBJECT = 0x6984;
    public static final short APPLICATION_NOT_FOUND_ERROR = 0x6a82;

    /**
     * Tlv tags for credential data
     */
    private static final byte TAG_NAME = 0x71;
    private static final byte TAG_KEY = 0x73;
    private static final byte TAG_RESPONSE = 0x75;
    private static final byte TAG_PROPERTY = 0x78;
    private static final byte TAG_IMF = 0x7a;
    private static final byte TAG_CHALLENGE = 0x74;

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

    private static final byte PROPERTY_REQUIRE_TOUCH = (byte)0x02;

    /**
     * Select OATH application APDU command data (for example for PIV application it's 0xa0, 0x00, 0x00, 0x03, 0x08)
     */
    private static final byte[] AID = new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01, 0x01};


    private static final long MILLS_IN_SECOND = 1000;
    private static final int DEFAULT_PERIOD = 30;

    /**
     * Version, ID and a challenge if authentication is configured
     */
    private final OathApplicationInfo applicationInfo;


    /**
     * Create new instance of {@link OathApplication}
     * and selects the application for use
     * @param session session with YubiKey
     * @throws IOException in case of connection error
     */
    public OathApplication(YubiKeySession session) throws IOException, ApduException, ApplicationNotFound {
        super(AID, session);
        try {
            applicationInfo = new OathApplicationInfo(select());
        } catch (ApduException e) {
            close();
            if (e.getStatusCode() == APPLICATION_NOT_FOUND_ERROR) {
                throw new ApplicationNotFound("OATH application is disabled on this device");
            } else {
                throw e;
            }
        } catch (IOException e) {
            close();
            throw e;
        }
    }

    /**
     * @return version, ID and a challenge if authentication is configured
     */
    public OathApplicationInfo getApplicationInfo() {
        return applicationInfo;
    }

    /**
     * Resets the application to just-installed state.
     * @throws IOException in case of connection error
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
     * @param password user-supplied password
     * @throws IOException in case of connection error
     * @return true if password valid
     */
    public boolean validate(String password) throws IOException, ApduException {
        // null password fail validation fast
        if (applicationInfo.isAuthenticationRequired() && TextUtils.isEmpty(password)) {
            return false;
        }

        final byte[] secret;
        try {
            secret = calculateSecret(password, applicationInfo.getDeviceId());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e); // This shouldn't happend.
        }

        return validate(new ChallengeSigner() {
            @Override
            public byte[] sign(byte[] challenge) throws InvalidKeyException, NoSuchAlgorithmException {
                return calculateResponse(secret, challenge);
            }
        });
    }

    /**
     * Validates authentication (mutually).
     * The challenge for this comes from the SELECT command.
     * The response if computed by performing the correct HMAC function of that challenge with the correct key.
     * A new challenge is then sent to the application, together with the response.
     * The application will then respond with a similar calculation that the host software can verify.
     * @param signer the provide of HMAC calculation
     * @throws IOException in case of connection error
     */
    public boolean validate(ChallengeSigner signer) throws IOException, ApduException {
        // if no validation/authentication required we consider that validation was successful
        if (!applicationInfo.isAuthenticationRequired()) {
            return true;
        }

        try {
            List<Tlv> requestTlv = new ArrayList<>();
            requestTlv.add(new Tlv(TAG_RESPONSE, signer.sign(applicationInfo.getChallenge())));

            byte[] challenge = generateChallenge();
            requestTlv.add(new Tlv(TAG_CHALLENGE, challenge));

            byte[] data = sendAndReceive(new Apdu(0, INS_VALIDATE, 0, 0, TlvUtils.packTlvList(requestTlv)));
            SparseArray<byte[]> map = TlvUtils.parseTlvMap(data);
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
     * @param password user-supplied password. If null or empty, authentication is removed.
     * @throws IOException in case of connection error
     */
    public void setPassword(String password) throws IOException, ApduException {
        final byte[] secret;
        try {
            secret = calculateSecret(password, applicationInfo.getDeviceId());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e); // This shouldn't happen
        }
        setSecret(secret);
    }

    /**
     * Configures Authentication.
     * If length 0 is sent, authentication is removed.
     * The key to be set is expected to be a user-supplied UTF-8 encoded password passed through 1000 rounds of PBKDF2
     * with the ID from select used as salt.
     * 16 bytes of that are used.
     * When configuring authentication you are required to send an 8 byte challenge and
     * one authentication-response with that key, in order to confirm that the application and
     * the host software can calculate the same response for that key.
     * @param secret 16 bytes of user-supplied UTF-8 encoded password passed through 1000 rounds of PBKDF2
     *               with the ID from select used as salt
     * @throws IOException in case of connection error
     */
    public void setSecret(byte[] secret) throws IOException, ApduException {
        final byte[] data;
        if (secret != null && secret.length > 0) {
            List<Tlv> requestTlv = new ArrayList<>();
            ByteArrayOutputStream keyStream = new ByteArrayOutputStream();
            keyStream.write(OathType.TOTP.value | HashAlgorithm.SHA1.value);
            keyStream.write(secret);
            requestTlv.add(new Tlv(TAG_KEY, keyStream.toByteArray()));

            byte[] challenge = generateChallenge();
            requestTlv.add(new Tlv(TAG_CHALLENGE, challenge));
            try {
                requestTlv.add(new Tlv(TAG_RESPONSE, calculateResponse(secret, challenge)));
                data = TlvUtils.packTlvList(requestTlv);
            } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                throw new RuntimeException(e); // This shouldn't happen
            }
        } else {
            // if secret passed null or empty remove password
            data = new byte[] {TAG_KEY, 0};
        }
        sendAndReceive(new Apdu(0, INS_SET_CODE, 0, 0, data));
    }

    /**
     * Lists configured credentials.
     * @return list of credentials on device
     * @throws IOException in case of connection error
     */
    public List<Credential> listCredentials() throws IOException, ApduException {
        byte[] response = sendAndReceive(new Apdu(0, INS_LIST, 0, 0, null));
        List<Tlv> list = TlvUtils.parseTlvList(response);
        List<Credential> result = new ArrayList<>();
        for (Tlv tlv : list) {
            result.add(new Credential(tlv.getValue(), tlv.getTag()));
        }
        return result;
    }

    /**
     * Performs CALCULATE for all available credentials,
     * @return returns credential + response for TOTP and just credential with null code for HOTP and credentials requiring touch.
     * @throws IOException in case of connection error
     */
    public Map<Credential, Code> calculateAll() throws IOException, ApduException {
        return calculateAll(System.currentTimeMillis());
    }

    /**
     * Performs CALCULATE for all available credentials,
     * @param timestamp the timestamp which is used as start point for TOTP
     * @return returns credential + response for TOTP and just credential for HOTP and credentials requiring touch.
     * @throws IOException in case of connection error
     */
    public Map<Credential, Code> calculateAll(long timestamp) throws IOException, ApduException {
        List<Tlv> requestTlv = new ArrayList<>();
        long timeStep = (timestamp / MILLS_IN_SECOND / DEFAULT_PERIOD);
        byte[] challenge = ByteBuffer.allocate(8).putLong(timeStep).array();

        // using default period to 30 second for all _credentials and then recalculate those that have different period
        requestTlv.add(new Tlv(TAG_CHALLENGE, challenge));
        byte[] data = sendAndReceive(new Apdu(0, INS_CALCULATE_ALL, 0, 1, TlvUtils.packTlvList(requestTlv)));
        Iterator<Tlv> responseTlv = TlvUtils.parseTlvList(data).iterator();
        Map<Credential, Code> map = new HashMap<>();
        while (responseTlv.hasNext()) {
            Tlv credentialTlv = responseTlv.next();
            Tlv codeTlv = responseTlv.next();

            // parse credential properties
            Credential credential = new Credential(credentialTlv.getValue(), credentialTlv.getTag(), codeTlv.getValue(), codeTlv.getTag());

            // parse code value (can be null for HOTP or credentials that require yubikey touch)
            String code = formatTruncated(codeTlv.getValue());

            if (!credential.isTruncated() || credential.getPeriod() != DEFAULT_PERIOD) {
                // recalculate credentials that have different period and that has non truncated result
                map.put(credential, calculate(credential, timestamp));
            } else if (!TextUtils.isEmpty(code)){
                // Note: codes are typically valid in 'DEFAULT_PERIOD' second slices
                // so the valid period actually starts before the calculation happens
                // and potentially might happen even way before (so that code is valid only 1 second after calculation)
                long validFrom = validFrom(timestamp, DEFAULT_PERIOD);
                map.put(credential, new Code(code, validFrom, validFrom + DEFAULT_PERIOD * MILLS_IN_SECOND));
            } else {
                map.put(credential, null);
            }
        }


        return map;
    }

    /**
     * Performs CALCULATE for one named credential.
     * @param credential credential that will get new code
     * @return calculated code
     * @throws IOException in case of connection error
     */
    public Code calculate(Credential credential) throws IOException, ApduException {
        return calculate(credential, System.currentTimeMillis());
    }

    /**
     * Performs CALCULATE for one named credential.
     * @param credential credential that will get new code
     * @param timestamp the timestamp which is used as start point for TOTP, can be null for HOTP
     * @return calculated code
     * @throws IOException in case of connection error
     */
    public Code calculate(Credential credential, @Nullable Long timestamp) throws IOException, ApduException {
        List<Tlv> requestTlv = new ArrayList<>();
        byte[] challenge;
        if (timestamp == null || credential.getPeriod() == 0) {
            challenge = new byte[8];
        } else {
            long timeStep = (timestamp / MILLS_IN_SECOND / credential.getPeriod());
            challenge = ByteBuffer.allocate(8).putLong(timeStep).array();
        }
        requestTlv.add(new Tlv(TAG_NAME, credential.getId().getBytes(StandardCharsets.UTF_8)));
        requestTlv.add(new Tlv(TAG_CHALLENGE, challenge));
        boolean truncate = credential.isTruncated();
        byte[] data = sendAndReceive(new Apdu(0, INS_CALCULATE, 0, truncate ? 1 : 0, TlvUtils.packTlvList(requestTlv)));
        Tlv responseTlv = new Tlv(data, 0);
        String value;
        if (truncate) {
            value = formatTruncated(responseTlv.getValue());
        } else {
            ByteBuffer byteBuffer = ByteBuffer.wrap(responseTlv.getValue());
            int offset = 0xf & byteBuffer.get(byteBuffer.remaining() - 1);
            int code = byteBuffer.getInt(offset + 1);
            value = Integer.toString(code);
        }

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
     * @param credential credential data to add
     * @throws IOException in case of connection error
     */
    public void putCredential(Credential credential) throws IOException, ApduException, NotSupportedOperation {
        if (credential.isTouch() && applicationInfo.getVersion().major < 4) {
            throw new NotSupportedOperation("Touch feature requires YubiKey 4 or later");
        }

        try {
            byte[] key = credential.getHashAlgorithm().prepareKey(credential.getSecret());
            List<Tlv> list = new ArrayList<>();
            list.add(new Tlv(TAG_NAME, credential.getId().getBytes(StandardCharsets.UTF_8)));

            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            stream.write((byte) (credential.getOathType().value | credential.getHashAlgorithm().value));
            stream.write((byte) credential.getDigits());
            stream.write(key, 0, key.length);
            list.add(new Tlv(TAG_KEY, stream.toByteArray()));

            ByteArrayOutputStream output = new ByteArrayOutputStream();
            output.write(TlvUtils.packTlvList(list));

            if (credential.isTouch()) {
                output.write(TAG_PROPERTY);
                output.write(PROPERTY_REQUIRE_TOUCH);
            }

            if (credential.getOathType() == OathType.HOTP && credential.getCounter() > 0) {
                output.write(TAG_IMF);
                output.write(4);
                output.write(ByteBuffer.allocate(4).putInt(credential.getCounter()).array());
            }

            Apdu apdu = new Apdu(0x00, INS_PUT, 0,0, output.toByteArray());
            sendAndReceive(apdu);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);  //This shouldn't happen
        }
    }

    /**
     * Deletes an existing credential.
     * @param credential credential data to remove
     * @throws IOException in case of connection error
     */
    public void deleteCredential(Credential credential) throws IOException, ApduException {
        List<Tlv> list = new ArrayList<>();
        list.add(new Tlv(TAG_NAME, credential.getId().getBytes(StandardCharsets.UTF_8)));
        Apdu apdu = new Apdu(0x00, INS_DELETE, 0,0, TlvUtils.packTlvList(list));
        sendAndReceive(apdu);
    }

    /**
     * Passes a user-supplied UTF-8 encoded password through 1000 rounds of PBKDF2
     * with the device ID from select used as salt. 16 bytes of that are used.
     * @param password a user-supplied password
     * @param salt the salt value (the deviceId returned by select command)
     * @return a secret/key for authentication
     * @throws InvalidKeySpecException in case of crypto operation error
     * @throws NoSuchAlgorithmException in case of crypto operation error
     */
    public static byte[] calculateSecret(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        if (TextUtils.isEmpty(password)) {
            return null;
        }

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec keyspec = new PBEKeySpec(password.toCharArray(), salt, 1000, 128);
        try {
            return factory.generateSecret(keyspec).getEncoded();
        } finally {
            keyspec.clearPassword();
        }
    }

    /**
     * Calculates HMAC (uses SHA1 as hash function)
     * @param secret the secret
     * @param message data in bytes
     * @return the MAC result
     * @throws InvalidKeyException in case of crypto operation error
     * @throws NoSuchAlgorithmException in case of crypto operation error
     */
    public static byte[] calculateResponse(byte[] secret, byte[] message) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac mac = Mac.getInstance("HmacSHA1"); //KeyProperties.KEY_ALGORITHM_HMAC_SHA1 on API 23+
        mac.init(new SecretKeySpec(secret, mac.getAlgorithm()));
        return mac.doFinal(message);
    }

    /**
     * Calculate the time when the valid period of code starts
     * @param timestamp current timestamp
     * @param period period in seconds for how long code is valid from its calculation/generation time
     * @return the start of period when code is valid
     */
    private static long validFrom(@Nullable Long timestamp, int period) {
        if (period == 0) {
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
     * @param data the code received within calculate or calculate all response
     * @return truncated code
     */
    private String formatTruncated(byte[] data) {
        String value;
        ByteBuffer byteBuffer = ByteBuffer.wrap(data);
        int digits = byteBuffer.get();
        if (byteBuffer.remaining() < 4) {
            // for codes that require touch we might not get code with calculate all
            return null;
        }
        String result = Integer.toString(byteBuffer.getInt());
        // truncate result length (align it with value of digits)
        if (result.length() > digits) {
            // take last digits
            value = result.substring(result.length() - digits);
        } else if (result.length() < digits) {
            // or append 0 at the beginning of string
            value = String.format("%" + digits + "s", result).replace(' ', '0');
        } else {
            value = result;
        }
        return value;
    }

    /**
     * Generated random 8 bytes that can be used as challenge for authentication
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

    /**
     * Uses ApduUtils.sendAndReceive method with specific ins byte for "send remaining data" command
     * @param command apdu command that will be sent
     * @return data that received from command execution
     * @throws IOException in case of connection error
     */
    @Override
    public byte[] sendAndReceive(Apdu command) throws IOException, ApduException {
        //YKOATH uses a non-standard INS for SEND_REMAINING.
        return ApduUtils.sendAndReceive(getConnection(), command, INS_SEND_REMAINING);
    }
}

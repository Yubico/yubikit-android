package com.yubico.yubikit.piv;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class Padding {
    private static final String RAW_RSA = "RSA/ECB/NoPadding";
    private static final Pattern ECDSA_HASH_PATTERN = Pattern.compile("^([A-Z]+)([0-9]*)withECDSA$", Pattern.CASE_INSENSITIVE);

    /**
     * Prepares a message for signing.
     *
     * @param keyType   the type of key to use for signing
     * @param message   the message to sign
     * @param algorithm the signature algorithm to use
     * @return the payload ready to be signed
     * @throws NoSuchAlgorithmException if the algorithm isn't supported
     */
    public static byte[] pad(KeyType keyType, byte[] message, String algorithm) throws NoSuchAlgorithmException {
        KeyType.KeyParams params = keyType.params;
        byte[] payload;
        switch (params.algorithm) {
            case RSA:
                // Sign using a dummy key
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(params.algorithm.name());
                kpg.initialize(params.bitLength);
                KeyPair kp = kpg.generateKeyPair();
                Signature signature = Signature.getInstance(algorithm);
                try {
                    // Do a "raw encrypt" of the signature to get the padded message
                    signature.initSign(kp.getPrivate());
                    signature.update(message);
                    Cipher rsa = Cipher.getInstance(RAW_RSA);
                    rsa.init(Cipher.ENCRYPT_MODE, kp.getPublic());
                    payload = rsa.doFinal(signature.sign());
                } catch (SignatureException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
                    throw new IllegalStateException(e); // Shouldn't happen
                } catch (NoSuchPaddingException e) {
                    throw new UnsupportedOperationException("SecurityProvider doesn't support RSA without padding", e);
                }
                break;
            case EC:
                Matcher matcher = ECDSA_HASH_PATTERN.matcher(algorithm);
                if (!matcher.find()) {
                    throw new IllegalArgumentException("Invalid algorithm for given key");
                }
                String md = matcher.group(1) + "-" + matcher.group(2);
                byte[] hash = MessageDigest.getInstance(md).digest(message);
                int byteLength = params.bitLength / 8;
                if (hash.length > byteLength) {
                    // Truncate
                    payload = Arrays.copyOf(hash, byteLength);
                } else if (hash.length < byteLength) {
                    // Leftpad, with no external dependencies!
                    payload = new byte[byteLength];
                    System.arraycopy(hash, 0, payload, payload.length - hash.length, hash.length);
                } else {
                    payload = hash;
                }
                break;
            default:
                throw new IllegalArgumentException();
        }

        return payload;
    }

    /**
     * Verifies and removes padding from a decrypted RSA message.
     *
     * @param decrypted the decrypted (but still padded) payload
     * @param algorithm the cipher algorithm used for encryption
     * @return the un-padded plaintext
     * @throws NoSuchPaddingException   in case the padding algorithm isn't supported
     * @throws NoSuchAlgorithmException in case the algorithm isn't supported
     * @throws BadPaddingException      in case of a padding error
     */
    public static byte[] unpad(byte[] decrypted, String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(algorithm);
        Cipher rsa = Cipher.getInstance(RAW_RSA);

        // Encrypt using a dummy key
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyType.Algorithm.RSA.name());
        kpg.initialize(decrypted.length * 8);
        KeyPair kp = kpg.generateKeyPair();
        try {
            rsa.init(Cipher.ENCRYPT_MODE, kp.getPublic());
            cipher.init(Cipher.DECRYPT_MODE, kp.getPrivate());
            return cipher.doFinal(rsa.doFinal(decrypted));
        } catch (InvalidKeyException | IllegalBlockSizeException e) {
            throw new IllegalStateException(e); // Shouldn't happen
        }
    }
}

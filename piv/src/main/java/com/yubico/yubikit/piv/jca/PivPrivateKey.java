package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.InvalidPinException;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;

import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.security.auth.DestroyFailedException;

public abstract class PivPrivateKey implements PrivateKey {
    final Slot slot;
    final KeyType keyType;
    protected final PivSession session;
    @Nullable
    private char[] pin;

    public static PivPrivateKey of(PivSession session, Slot slot, KeyType keyType, @Nullable char[] pin) {
        switch (keyType.params.algorithm) {
            case EC:
                return new PivEcPrivateKey(session, slot, keyType, pin);
            case RSA:
                return new PivRsaPrivateKey(session, slot, keyType, pin);
        }
        throw new IllegalArgumentException();
    }

    private static class PivEcPrivateKey extends PivPrivateKey implements ECKey {
        private PivEcPrivateKey(PivSession session, Slot slot, KeyType keyType, @Nullable char[] pin) {
            super(session, slot, keyType, pin);
        }

        @Override
        public ECParameterSpec getParams() {
            try {
                ECPublicKey publicKey = (ECPublicKey)session.getCertificate(slot).getPublicKey();
                return publicKey.getParams();
            } catch (IOException exception) {
                exception.printStackTrace();
            } catch (ApduException e) {
                e.printStackTrace();
            } catch (BadResponseException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    private static class PivRsaPrivateKey extends PivPrivateKey implements RSAKey {
        private PivRsaPrivateKey(PivSession session, Slot slot, KeyType keyType, @Nullable char[] pin) {
            super(session, slot, keyType, pin);
        }

        @Override
        public BigInteger getModulus() {
            try {
                RSAPublicKey publicKey = (RSAPublicKey)session.getCertificate(slot).getPublicKey();
                Logger.d("Using public key: " + publicKey);
                return publicKey.getModulus();
            } catch (IOException exception) {
                exception.printStackTrace();
            } catch (ApduException e) {
                e.printStackTrace();
            } catch (BadResponseException e) {
                e.printStackTrace();
            }
            return null;
        }
    }

    private PivPrivateKey(PivSession session, Slot slot, KeyType keyType, @Nullable char[] pin) {
        this.session = session;
        this.slot = slot;
        this.keyType = keyType;
        this.pin = pin != null ? Arrays.copyOf(pin, pin.length) : null;
    }

    @Override
    public void destroy() throws DestroyFailedException {
        if (pin != null) {
            Arrays.fill(pin, (char) 0);
            pin = null;
        }
    }

    @Override
    public boolean isDestroyed() {
        return pin == null;
    }

    byte[] sign(byte[] message, Signature algorithm) {
        try {
            if (pin != null) {
                session.verifyPin(pin);
            }
            return session.sign(slot, keyType, message, algorithm);
        } catch (IOException | InvalidPinException | NoSuchAlgorithmException | BadResponseException | ApduException e) {
            Logger.e("Error signing message", e);
        }
        throw new UnsupportedOperationException();
    }

    byte[] decrypt(byte[] cipherText, Cipher algorithm) throws InvalidKeyException, BadPaddingException {
        if (keyType.params.algorithm != KeyType.Algorithm.RSA) {
            throw new InvalidKeyException("Decrypt only available for RSA keys");
        }
        try {
            if (pin != null) {
                session.verifyPin(pin);
            }
            return session.decrypt(slot, cipherText, algorithm);
        } catch (IOException | ApduException | BadResponseException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidPinException e) {
            Logger.e("Error decrypting message", e);
        }
        throw new UnsupportedOperationException();
    }

    byte[] keyAgreement(ECPublicKey peerPublicKey) throws InvalidKeyException {
        if (keyType.params.algorithm != KeyType.Algorithm.EC) {
            throw new InvalidKeyException("KeyAgreement only available for EC keys");
        }
        try {
            if (pin != null) {
                session.verifyPin(pin);
            }
            return session.calculateSecret(slot, peerPublicKey);
        } catch (IOException | ApduException | InvalidPinException | BadResponseException e) {
            Logger.e("Error performing key agreement", e);
        }
        throw new UnsupportedOperationException();
    }

    @Override
    public String getAlgorithm() {
        return keyType.params.algorithm.name();
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return null;
    }
}

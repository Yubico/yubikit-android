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
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;

import javax.annotation.Nullable;
import javax.security.auth.DestroyFailedException;

public abstract class PivPrivateKey implements PrivateKey {
    final Slot slot;
    final KeyType keyType;
    protected final PivSession session;
    @Nullable
    protected final Pin pin;

    public static PivPrivateKey of(PivSession session, Slot slot, KeyType keyType, @Nullable Pin pin) {
        switch (keyType.params.algorithm) {
            case EC:
                return new EcKey(session, slot, keyType, pin);
            case RSA:
                return new RsaKey(session, slot, keyType, pin);
        }
        throw new IllegalArgumentException();
    }

    private PivPrivateKey(PivSession session, Slot slot, KeyType keyType, @Nullable Pin pin) {
        this.session = session;
        this.slot = slot;
        this.keyType = keyType;
        this.pin = pin;
    }

    @Override
    public void destroy() throws DestroyFailedException {
        if (pin != null) {
            pin.destroy();
        }
    }

    @Override
    public boolean isDestroyed() {
        return pin == null || pin.isDestroyed();
    }

    byte[] apply(byte[] message) {
        try {
            if (pin != null && !pin.isDestroyed()) {
                session.verifyPin(pin.buffer);
            }
            return session.rawSignOrDecrypt(slot, keyType, message);
        } catch (IOException | InvalidPinException | NoSuchAlgorithmException | BadResponseException | ApduException e) {
            Logger.e("Error signing message", e);
        }
        throw new UnsupportedOperationException();
    }

    @Override
    public String getAlgorithm() {
        return keyType.params.algorithm.name();
    }

    @Override
    @Nullable
    public String getFormat() {
        return null;
    }

    @Override
    @Nullable
    public byte[] getEncoded() {
        return null;
    }

    static class EcKey extends PivPrivateKey implements ECKey {
        private EcKey(PivSession session, Slot slot, KeyType keyType, @Nullable Pin pin) {
            super(session, slot, keyType, pin);
        }

        @Override
        public ECParameterSpec getParams() {
            try {
                ECPublicKey publicKey = (ECPublicKey)JcaUtils.getPublicKey(session, slot);
                Logger.d("Reading EC params from public key: " + publicKey);
                return publicKey.getParams();
            } catch (IOException | ApduException e) {
                Logger.e("Error reading public key", e);
                throw new UnsupportedOperationException();
            }
        }

        byte[] keyAgreement(ECPublicKey peerPublicKey) throws InvalidKeyException {
            if (keyType.params.algorithm != KeyType.Algorithm.EC) {
                throw new InvalidKeyException("KeyAgreement only available for EC keys");
            }
            try {
                if (pin != null && !pin.isDestroyed()) {
                    session.verifyPin(pin.buffer);
                }
                return session.calculateSecret(slot, peerPublicKey);
            } catch (IOException | ApduException | InvalidPinException | BadResponseException e) {
                Logger.e("Error performing key agreement", e);
            }
            throw new UnsupportedOperationException();
        }
    }

    static class RsaKey extends PivPrivateKey implements RSAKey {
        private RsaKey(PivSession session, Slot slot, KeyType keyType, @Nullable Pin pin) {
            super(session, slot, keyType, pin);
        }

        @Override
        public BigInteger getModulus() {
            try {
                RSAPublicKey publicKey = (RSAPublicKey)JcaUtils.getPublicKey(session, slot);
                Logger.d("Reading modulus from public key: " + publicKey);
                return publicKey.getModulus();
            } catch (IOException | ApduException e) {
                Logger.e("Error reading public key", e);
                throw new UnsupportedOperationException();
            }
        }
    }
}

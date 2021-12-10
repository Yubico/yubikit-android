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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.function.Function;

import javax.annotation.Nullable;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

public abstract class PivPrivateKey implements PrivateKey {
    final Slot slot;
    final KeyType keyType;
    protected final PivSessionProvider sessionProvider;

    public static PivPrivateKey of(PublicKey publicKey, Slot slot, PivSessionProvider sessionProvider) {
        KeyType keyType = KeyType.fromKey(publicKey);
        switch (keyType.params.algorithm) {
            case EC:
                return new EcKey(sessionProvider, slot, keyType, ((ECPublicKey)publicKey).getParams());
            case RSA:
                return new RsaKey(sessionProvider, slot, keyType, ((RSAPublicKey)publicKey).getModulus());
        }
        throw new IllegalArgumentException();
    }

    private PivPrivateKey(PivSessionProvider sessionProvider, Slot slot, KeyType keyType) {
        this.sessionProvider = sessionProvider;
        this.slot = slot;
        this.keyType = keyType;
    }

    byte[] apply(byte[] message) {
        byte[] result = sessionProvider.use((session) -> {
            try {
                return session.rawSignOrDecrypt(slot, keyType, message);
            } catch (IOException | ApduException | BadResponseException e) {
                Logger.e("Error signing message", e);
                return null;
            }
        });
        if(result != null) {
            return result;
        }
        throw new UnsupportedOperationException();
    }

    @Override
    public void destroy() throws DestroyFailedException {
        if (sessionProvider instanceof Destroyable) {
            ((Destroyable) sessionProvider).destroy();
        } else {
            throw new DestroyFailedException();
        }
    }

    @Override
    public boolean isDestroyed() {
        if (sessionProvider instanceof Destroyable) {
            return ((Destroyable) sessionProvider).isDestroyed();
        }
        return false;
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
        private final ECParameterSpec params;
        private EcKey(PivSessionProvider sessionProvider, Slot slot, KeyType keyType, ECParameterSpec params) {
            super(sessionProvider, slot, keyType);
            this.params = params;
        }

        @Override
        public ECParameterSpec getParams() {
            return params;
        }

        byte[] keyAgreement(ECPublicKey peerPublicKey) throws InvalidKeyException {
            byte[] result = sessionProvider.use((session) -> {
                try {
                    return session.calculateSecret(slot, peerPublicKey);
                } catch (IOException | ApduException | BadResponseException e) {
                    Logger.e("Error performing key agreement", e);
                    return null;
                }
            });
            if(result != null) {
                return result;
            }
            throw new UnsupportedOperationException();
        }
    }

    static class RsaKey extends PivPrivateKey implements RSAKey {
        private final BigInteger modulus;
        private RsaKey(PivSessionProvider getSession, Slot slot, KeyType keyType, BigInteger modulus) {
            super(getSession, slot, keyType);
            this.modulus = modulus;
        }

        @Override
        public BigInteger getModulus() {
            return modulus;
        }
    }

}

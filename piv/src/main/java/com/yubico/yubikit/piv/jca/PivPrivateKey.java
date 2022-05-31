package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import javax.annotation.Nullable;

public abstract class PivPrivateKey implements PrivateKey {
    final Slot slot;
    final KeyType keyType;
    @Nullable
    protected final char[] pin;
    private boolean destroyed = false;

    public static PivPrivateKey from(PublicKey publicKey, Slot slot, @Nullable char[] pin) {
        KeyType keyType = KeyType.fromKey(publicKey);
        if (keyType.params.algorithm == KeyType.Algorithm.RSA) {
            return new PivPrivateKey.RsaKey(slot, keyType, ((RSAPublicKey) publicKey).getModulus(), pin);
        } else {
            return new PivPrivateKey.EcKey(slot, keyType, ((ECPublicKey) publicKey), pin);
        }
    }

    protected PivPrivateKey(Slot slot, KeyType keyType, @Nullable char[] pin) {
        this.slot = slot;
        this.keyType = keyType;
        this.pin = pin != null ? Arrays.copyOf(pin, pin.length) : null;
    }

    byte[] rawSignOrDecrypt(Callback<Callback<Result<PivSession, Exception>>> provider, byte[] payload) throws Exception {
        BlockingQueue<Result<byte[], Exception>> queue = new ArrayBlockingQueue<>(1);
        provider.invoke(result -> queue.add(Result.of(() -> {
            PivSession session = result.getValue();
            if (pin != null) {
                session.verifyPin(pin);
            }
            return session.rawSignOrDecrypt(slot, keyType, payload);
        })));
        return queue.take().getValue();
    }

    @Override
    public void destroy() {
        if (pin != null) {
            Arrays.fill(pin, (char) 0);
        }
        destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
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
        private final ECPublicKey publicKey;

        private EcKey(Slot slot, KeyType keyType, ECPublicKey publicKey, @Nullable char[] pin) {
            super(slot, keyType, pin);
            this.publicKey = publicKey;
        }

        byte[] keyAgreement(Callback<Callback<Result<PivSession, Exception>>> provider, ECPublicKey peerPublicKey) throws Exception {
            BlockingQueue<Result<byte[], Exception>> queue = new ArrayBlockingQueue<>(1);
            provider.invoke(result -> queue.add(Result.of(() -> {
                PivSession session = result.getValue();
                if (pin != null) {
                    session.verifyPin(pin);
                }
                return session.calculateSecret(slot, peerPublicKey);
            })));
            return queue.take().getValue();
        }

        @Override
        public ECParameterSpec getParams() {
            return publicKey.getParams();
        }
    }

    static class RsaKey extends PivPrivateKey implements RSAKey {
        private final BigInteger modulus;

        private RsaKey(Slot slot, KeyType keyType, BigInteger modulus, @Nullable char[] pin) {
            super(slot, keyType, pin);
            this.modulus = modulus;
        }

        @Override
        public BigInteger getModulus() {
            return modulus;
        }
    }
}

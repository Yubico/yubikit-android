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
import java.util.concurrent.CompletableFuture;

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
            return new PivPrivateKey.EcKey(slot, keyType, ((ECPublicKey) publicKey).getParams(), pin);
        }
    }

    public PivPrivateKey(Slot slot, KeyType keyType, @Nullable char[] pin) {
        this.slot = slot;
        this.keyType = keyType;
        this.pin = pin != null ? Arrays.copyOf(pin, pin.length) : null;
    }

    byte[] rawSignOrDecrypt(Callback<Callback<Result<PivSession, Exception>>> provider, byte[] payload) throws Exception {
        CompletableFuture<Result<byte[], Exception>> future = new CompletableFuture<>();
        provider.invoke(result -> future.complete(Result.of(() -> {
            PivSession session = result.getValue();
            if (pin != null) {
                session.verifyPin(pin);
            }
            return session.rawSignOrDecrypt(slot, keyType, payload);
        })));
        return future.get().getValue();
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
        private final ECParameterSpec params;  //TODO: Get this from KeyType?

        private EcKey(Slot slot, KeyType keyType, ECParameterSpec params, @Nullable char[] pin) {
            super(slot, keyType, pin);
            this.params = params;
        }

        byte[] keyAgreement(Callback<Callback<Result<PivSession, Exception>>> provider, ECPublicKey peerPublicKey) throws Exception {
            CompletableFuture<Result<byte[], Exception>> future = new CompletableFuture<>();
            provider.invoke(result -> future.complete(Result.of(() -> {
                PivSession session = result.getValue();
                if (pin != null) {
                    session.verifyPin(pin);
                }
                return session.calculateSecret(slot, peerPublicKey);
            })));
            return future.get().getValue();
        }

        @Override
        public ECParameterSpec getParams() {
            return params;
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

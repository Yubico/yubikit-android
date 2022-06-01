package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;

import javax.annotation.Nullable;

abstract class PivKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private final Callback<Callback<Result<PivSession, Exception>>> provider;
    private final KeyType.Algorithm algorithm;

    PivKeyPairGeneratorSpi(Callback<Callback<Result<PivSession, Exception>>> provider, KeyType.Algorithm algorithm) {
        this.provider = provider;
        this.algorithm = algorithm;
    }

    @Nullable
    PivAlgorithmParameterSpec spec;

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params instanceof PivAlgorithmParameterSpec) {
            spec = (PivAlgorithmParameterSpec) params;
            if (spec.keyType.params.algorithm != algorithm) {
                throw new InvalidAlgorithmParameterException("Invalid key algorithm for this KeyPairGenerator");
            }
        } else {
            throw new InvalidAlgorithmParameterException("Must be instance of PivAlgorithmParameterSpec");
        }
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
        throw new IllegalArgumentException("Initialize with PivAlgorithmParameterSpec!");
    }

    @Override
    public KeyPair generateKeyPair() {
        if (spec == null) {
            throw new IllegalStateException("KeyPairGenerator not initialized!");
        }
        try {
            BlockingQueue<Result<KeyPair, Exception>> queue = new ArrayBlockingQueue<>(1);
            provider.invoke(result -> queue.add(Result.of(() -> {
                PivSession session = result.getValue();
                PublicKey publicKey = session.generateKey(spec.slot, spec.keyType, spec.pinPolicy, spec.touchPolicy);
                PrivateKey privateKey = PivPrivateKey.from(publicKey, spec.slot, spec.pinPolicy, spec.touchPolicy, spec.pin);
                return new KeyPair(publicKey, privateKey);
            })));
            return queue.take().getValue();
        } catch (Exception e) {
            throw new IllegalStateException("An error occurred when generating the key pair", e);
        }
    }

    public static class Rsa extends PivKeyPairGeneratorSpi {
        Rsa(Callback<Callback<Result<PivSession, Exception>>> provider) {
            super(provider, KeyType.Algorithm.RSA);
        }
    }

    public static class Ec extends PivKeyPairGeneratorSpi {
        Ec(Callback<Callback<Result<PivSession, Exception>>> provider) {
            super(provider, KeyType.Algorithm.EC);
        }
    }
}

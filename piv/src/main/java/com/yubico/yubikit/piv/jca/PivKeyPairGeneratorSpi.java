package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.KeyType;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.Nullable;

abstract class PivKeyPairGeneratorSpi extends KeyPairGeneratorSpi {
    private KeyType keyType;

    PivKeyPairGeneratorSpi(KeyType defaultKeyType) {
        keyType = defaultKeyType;
    }

    @Nullable
    PivAlgorithmParameterSpec spec;

    @Override
    public void initialize(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (params instanceof PivAlgorithmParameterSpec) {
            this.spec = (PivAlgorithmParameterSpec) params;
        } else {
            throw new InvalidAlgorithmParameterException("Must be instance of PivAlgorithmParameterSpec");
        }
    }

    @Override
    public void initialize(int keySize, SecureRandom random) {
        keyType = getKeyType(keySize);
    }

    @Override
    public KeyPair generateKeyPair() {
        if (spec == null) {
            throw new IllegalStateException("KeyPairGenerator not initialized!");
        }
        try {
            PublicKey publicKey = spec.piv.generateKey(spec.slot, keyType, spec.pinPolicy, spec.touchPolicy);
            PrivateKey privateKey = PivPrivateKey.of(spec.piv, spec.slot, keyType, spec.pin);
            return new KeyPair(publicKey, privateKey);
        } catch (IOException | ApduException | BadResponseException e) {
            throw new RuntimeException(e);
        }
    }

    protected abstract KeyType getKeyType(int keySize);

    public static class Rsa extends PivKeyPairGeneratorSpi {
        public Rsa() {
            super(KeyType.RSA2048);
        }

        @Override
        protected KeyType getKeyType(int keySize) {
            switch (keySize) {
                case 1024:
                    return KeyType.RSA1024;
                case 2048:
                    return KeyType.RSA2048;
                default:
                    throw new InvalidParameterException("Unsupported RSA key size");

            }
        }
    }

    public static class Ec extends PivKeyPairGeneratorSpi {
        public Ec() {
            super(KeyType.ECCP256);
        }

        @Override
        protected KeyType getKeyType(int keySize) {
            switch (keySize) {
                case 256:
                    return KeyType.ECCP256;
                case 384:
                    return KeyType.ECCP384;
                default:
                    throw new InvalidParameterException("Unsupported EC key size");
            }
        }
    }
}

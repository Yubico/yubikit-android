package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.Nullable;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

public class PivKeyAgreementSpi extends KeyAgreementSpi {
    private final Callback<Callback<Result<PivSession, Exception>>> provider;
    @Nullable
    private PivPrivateKey.EcKey privateKey;
    @Nullable
    private ECPublicKey publicKey;

    PivKeyAgreementSpi(Callback<Callback<Result<PivSession, Exception>>> provider) {
        this.provider = provider;
    }

    @Override
    protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
        if (key instanceof PivPrivateKey.EcKey) {
            privateKey = (PivPrivateKey.EcKey) key;
        } else {
            throw new InvalidKeyException("Key must be instance of PivPrivateKey");
        }
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(key, random);
    }

    @Override
    @Nullable
    protected Key engineDoPhase(Key key, boolean lastPhase) throws InvalidKeyException, IllegalStateException {
        if (privateKey == null) {
            throw new IllegalStateException("KeyAgreement not initialized");
        }
        if (!lastPhase) {
            throw new IllegalStateException("Multiple phases not supported");
        }
        if (key instanceof PublicKey && KeyType.fromKey(key) == privateKey.keyType) {
            publicKey = (ECPublicKey) key;
            return null;
        }
        throw new InvalidKeyException("Wrong key type");
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (privateKey != null && publicKey != null) {
            try {
                return privateKey.keyAgreement(provider, publicKey);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            } finally {
                publicKey = null;
            }
        }
        throw new IllegalStateException("Not initialized with both private and public keys");
    }

    @Override
    protected int engineGenerateSecret(byte[] sharedSecret, int offset) throws IllegalStateException, ShortBufferException {
        byte[] result = engineGenerateSecret();
        try {
            System.arraycopy(result, 0, sharedSecret, offset, result.length);
            return result.length;
        } catch (IndexOutOfBoundsException e) {
            throw new ShortBufferException();
        }
    }

    @Override
    protected SecretKey engineGenerateSecret(String algorithm) throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
        throw new IllegalStateException("Not supported");
    }
}

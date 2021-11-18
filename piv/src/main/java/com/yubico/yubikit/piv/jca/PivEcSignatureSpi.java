package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.piv.KeyType;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;

import javax.annotation.Nullable;

public abstract class PivEcSignatureSpi extends SignatureSpi {
    @Nullable
    private PivPrivateKey privateKey;

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        throw new InvalidKeyException("Can only be used for signing.");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof PivPrivateKey) {
            if (((PivPrivateKey) privateKey).keyType.params.algorithm != KeyType.Algorithm.EC) {
                throw new InvalidKeyException("Must be EC key");
            }
            this.privateKey = (PivPrivateKey) privateKey;
        } else {
            throw new InvalidKeyException("Unsupported key type");
        }
    }

    protected abstract void update(byte b);

    protected abstract void update(byte[] b, int off, int len);

    protected abstract byte[] digest();

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (privateKey != null) {
            update(b);
        } else {
            throw new SignatureException("Not initialized");
        }
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (privateKey != null) {
            update(b, off, len);
        } else {
            throw new SignatureException("Not initialized");
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) {
            throw new SignatureException("Not initialized");
        }
        return privateKey.apply(digest());
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new SignatureException("Not initialized");
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        throw new InvalidParameterException("ECDSA doesn't take parameters");
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        throw new InvalidParameterException("ECDSA doesn't take parameters");
    }

    public static class Prehashed extends PivEcSignatureSpi {
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            super.engineInitSign(privateKey);
            buffer.reset();
        }

        @Override
        protected void update(byte b) {
            buffer.write(b);
        }

        @Override
        protected void update(byte[] b, int off, int len) {
            buffer.write(b, off, len);
        }

        @Override
        protected byte[] digest() {
            return buffer.toByteArray();
        }
    }

    public static class Hashed extends PivEcSignatureSpi {
        private final MessageDigest digest;

        Hashed(String algorithm) throws NoSuchAlgorithmException {
            digest = MessageDigest.getInstance(algorithm);
        }

        @Override
        protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
            super.engineInitSign(privateKey);
            digest.reset();
        }

        @Override
        protected void update(byte b) {
            digest.update(b);
        }

        @Override
        protected void update(byte[] b, int off, int len) {
            digest.update(b, off, len);
        }

        @Override
        protected byte[] digest() {
            return digest.digest();
        }
    }
}

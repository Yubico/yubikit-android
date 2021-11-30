package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.piv.KeyType;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;

import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class PivRsaSignatureSpi extends SignatureSpi {
    private final Map<KeyType, KeyPair> dummyKeys;
    private final String signature;

    @Nullable
    private PivPrivateKey.RsaKey privateKey;

    @Nullable
    private Signature delegate;

    public PivRsaSignatureSpi(Map<KeyType, KeyPair> dummyKeys, String signature) throws NoSuchPaddingException {
        this.dummyKeys = dummyKeys;
        this.signature = signature;
    }

    private Signature getDelegate(boolean init) throws NoSuchAlgorithmException {
        if (delegate == null) {
            delegate = Signature.getInstance(signature);
            // If parameters are set before initSign is called we need to initialize the delegate to choose Provider.
            if (init) {
                try {
                    // Key size may be wrong, but that will get fixes once initSign is called.
                    delegate.initSign(dummyKeys.get(KeyType.RSA2048).getPrivate());
                } catch (InvalidKeyException e) {
                    throw new NoSuchAlgorithmException();
                }
            }
        }
        return delegate;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        throw new InvalidKeyException("Can only be used for signing.");
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof PivPrivateKey.RsaKey) {
            this.privateKey = (PivPrivateKey.RsaKey) privateKey;
            KeyPair dummyPair = dummyKeys.get(this.privateKey.keyType);
            try {
                getDelegate(false).initSign(dummyPair.getPrivate());
            } catch (NoSuchAlgorithmException e) {
                throw new InvalidKeyException(e);
            }
        } else {
            throw new InvalidKeyException("Unsupported key type");
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (delegate != null) {
            delegate.update(b);
        } else {
            throw new SignatureException("Not initialized");
        }
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (delegate != null) {
            delegate.update(b, off, len);
        } else {
            throw new SignatureException("Not initialized");
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null || delegate == null) {
            throw new SignatureException("Not initialized");
        }
        try {
            Cipher rawRsa = Cipher.getInstance("RSA/ECB/NoPadding");
            rawRsa.init(Cipher.ENCRYPT_MODE, dummyKeys.get(this.privateKey.keyType).getPublic());
            byte[] padded = rawRsa.doFinal(delegate.sign());
            return privateKey.apply(padded);
        } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
            throw new SignatureException(e);
        }
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        throw new SignatureException("Not initialized");
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        try {
            getDelegate(true).setParameter(param, value);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidParameterException("Not initialized");
        }
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        if (delegate != null) {
            return delegate.getParameter(param);
        } else {
            throw new InvalidParameterException("Not initialized");
        }
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        try {
            getDelegate(true).setParameter(params);
        } catch (NoSuchAlgorithmException e) {
            throw new InvalidParameterException("Not initialized");
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (delegate != null) {
            return delegate.getParameters();
        } else {
            throw new InvalidParameterException("Not initialized");
        }
    }
}

package com.yubico.yubikit.piv.jca;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.Nullable;

public class PivSignatureSpi extends SignatureSpi {
    private final Signature delegate;
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();

    @Nullable
    private PivPrivateKey privateKey;

    public PivSignatureSpi(Signature delegate) {
        this.delegate = delegate;
    }

    @Override
    protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
        delegate.initVerify(publicKey);
        privateKey = null;
        buffer.reset();
    }

    @Override
    protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
        if (privateKey instanceof PivPrivateKey) {
            this.privateKey = (PivPrivateKey) privateKey;
            buffer.reset();
        } else {
            throw new InvalidKeyException("Unsupported key type");
        }
    }

    @Override
    protected void engineUpdate(byte b) throws SignatureException {
        if (privateKey != null) {
            buffer.write(b);
        } else {
            delegate.update(b);
        }
    }

    @Override
    protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
        if (privateKey != null) {
            buffer.write(b, off, len);
        } else {
            delegate.update(b, off, len);
        }
    }

    @Override
    protected byte[] engineSign() throws SignatureException {
        if (privateKey == null) {
            throw new SignatureException("Not initialized");
        }
        byte[] message = buffer.toByteArray();
        buffer.reset();
        return privateKey.sign(message, delegate);
    }

    @Override
    protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
        return delegate.verify(sigBytes);
    }

    @Override
    protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
        delegate.setParameter(param, value);
    }

    @Override
    protected Object engineGetParameter(String param) throws InvalidParameterException {
        return delegate.getParameter(param);
    }

    @Override
    protected void engineSetParameter(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
        delegate.setParameter(params);
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return delegate.getParameters();
    }
}

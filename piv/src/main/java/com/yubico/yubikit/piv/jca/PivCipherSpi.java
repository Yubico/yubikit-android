package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.piv.KeyType;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

public class PivCipherSpi extends CipherSpi {
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    @Nullable
    private PivPrivateKey privateKey;
    @Nullable
    private String mode;
    @Nullable
    private String padding;
    private int opmode = -1;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        this.mode = mode;
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        this.padding = padding;
    }

    @Override
    protected int engineGetBlockSize() {
        if (privateKey == null) {
            throw new IllegalStateException("Cipher not initialized");
        }
        return privateKey.keyType.params.bitLength / 8;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        return engineGetBlockSize();
    }

    @Override
    protected byte[] engineGetIV() {
        return new byte[0];
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (key instanceof PivPrivateKey) {
            if (!KeyType.Algorithm.RSA.name().equals(key.getAlgorithm())) {
                throw new InvalidKeyException("Cipher only supports RSA.");
            }
            privateKey = (PivPrivateKey) key;
            this.opmode = opmode;
            buffer.reset();
        } else {
            throw new InvalidKeyException("Unsupported key type");
        }
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(opmode, key, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        buffer.write(input, inputOffset, inputLen);
        return new byte[0];
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException {
        buffer.write(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen) throws IllegalBlockSizeException, BadPaddingException {
        buffer.write(input, inputOffset, inputLen);
        byte[] cipherText = buffer.toByteArray();
        if (privateKey == null) {
            throw new IllegalStateException("Cipher not initialized");
        }
        try {
            switch (opmode) {
                case Cipher.DECRYPT_MODE:
                    return privateKey.decrypt(cipherText, getDelegate());
                case Cipher.ENCRYPT_MODE:
                    if ("NoPadding".equals(padding)) {
                        return privateKey.decrypt(cipherText, getDelegate());
                    } else {
                        return privateKey.sign(cipherText, Signature.getInstance("NONEwithRSA"));
                    }
                default:
                    throw new UnsupportedOperationException();
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException(e);
        }
    }

    private Cipher getDelegate() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance("RSA/" + mode + "/" + padding);
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        byte[] result = engineDoFinal(input, inputOffset, inputLen);
        try {
            System.arraycopy(result, 0, output, outputOffset, result.length);
            return result.length;
        } catch (IndexOutOfBoundsException e) {
            throw new ShortBufferException();
        }
    }
}

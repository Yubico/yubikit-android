/*
 * Copyright (C) 2022 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.piv.PivSession;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECPoint;

import javax.annotation.Nullable;
import javax.crypto.KeyAgreementSpi;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

public class PivKeyAgreementSpi extends KeyAgreementSpi {
    private final Callback<Callback<Result<PivSession, Exception>>> provider;
    @Nullable
    private PivPrivateKey.EcKey privateKey;
    @Nullable
    private ECPoint publicPoint;

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
        if(key instanceof ECPublicKey && privateKey.getParams().getCurve().equals(((ECPublicKey) key).getParams().getCurve())) {
            publicPoint = ((ECPublicKey) key).getW();
            return null;
        }
        throw new InvalidKeyException("Wrong key type");
    }

    @Override
    protected byte[] engineGenerateSecret() throws IllegalStateException {
        if (privateKey != null && publicPoint != null) {
            try {
                return privateKey.keyAgreement(provider, publicPoint);
            } catch (Exception e) {
                throw new IllegalStateException(e);
            } finally {
                publicPoint = null;
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

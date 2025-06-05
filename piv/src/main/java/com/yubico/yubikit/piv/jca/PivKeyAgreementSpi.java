/*
 * Copyright (C) 2022,2024 Yubico.
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

import com.yubico.yubikit.core.keys.EllipticCurveValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
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
  @Nullable private PivPrivateKey privateKey;
  @Nullable private PublicKeyValues publicKeyValues;

  PivKeyAgreementSpi(Callback<Callback<Result<PivSession, Exception>>> provider) {
    this.provider = provider;
  }

  @Override
  protected void engineInit(Key key, SecureRandom random) throws InvalidKeyException {
    if (key instanceof PivPrivateKey.EcKey) {
      privateKey = (PivPrivateKey.EcKey) key;
    } else if (key instanceof PivPrivateKey.X25519Key) {
      privateKey = (PivPrivateKey.X25519Key) key;
    } else {
      throw new InvalidKeyException("Key must be instance of PivPrivateKey");
    }
  }

  @Override
  protected void engineInit(Key key, AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    engineInit(key, random);
  }

  @Override
  @Nullable
  protected Key engineDoPhase(Key key, boolean lastPhase)
      throws InvalidKeyException, IllegalStateException {
    if (privateKey == null) {
      throw new IllegalStateException("KeyAgreement not initialized");
    }
    if (!lastPhase) {
      throw new IllegalStateException("Multiple phases not supported");
    }

    if (privateKey instanceof PivPrivateKey.EcKey && key instanceof ECPublicKey) {
      PivPrivateKey.EcKey pivEcPrivateKey = (PivPrivateKey.EcKey) privateKey;
      ECPublicKey ecPublicKey = (ECPublicKey) key;

      if (pivEcPrivateKey.getParams().getCurve().equals(ecPublicKey.getParams().getCurve())) {
        publicKeyValues = PublicKeyValues.fromPublicKey(ecPublicKey);
        return null;
      }
    } else if (privateKey instanceof PivPrivateKey.X25519Key && key instanceof PublicKey) {
      publicKeyValues = PublicKeyValues.fromPublicKey((PublicKey) key);
      if (publicKeyValues instanceof PublicKeyValues.Cv25519) {
        PublicKeyValues.Cv25519 cv25519PublicKeyValues = (PublicKeyValues.Cv25519) publicKeyValues;
        if (cv25519PublicKeyValues.getCurveParams() == EllipticCurveValues.X25519) {
          return null;
        }
      }
    }

    throw new InvalidKeyException("Wrong key type");
  }

  @Override
  protected byte[] engineGenerateSecret() throws IllegalStateException {
    if (privateKey != null && publicKeyValues != null) {
      try {
        if (privateKey instanceof PivPrivateKey.EcKey) {
          return ((PivPrivateKey.EcKey) privateKey).keyAgreement(provider, publicKeyValues);
        } else if (privateKey instanceof PivPrivateKey.X25519Key) {
          return ((PivPrivateKey.X25519Key) privateKey).keyAgreement(provider, publicKeyValues);
        }
      } catch (Exception e) {
        throw new IllegalStateException(e);
      } finally {
        publicKeyValues = null;
      }
    }
    throw new IllegalStateException("Not initialized with both private and public keys");
  }

  @Override
  protected int engineGenerateSecret(byte[] sharedSecret, int offset)
      throws IllegalStateException, ShortBufferException {
    byte[] result = engineGenerateSecret();
    try {
      System.arraycopy(result, 0, sharedSecret, offset, result.length);
      return result.length;
    } catch (IndexOutOfBoundsException e) {
      throw new ShortBufferException();
    }
  }

  @Override
  protected SecretKey engineGenerateSecret(String algorithm)
      throws IllegalStateException, NoSuchAlgorithmException, InvalidKeyException {
    throw new IllegalStateException("Not supported");
  }
}

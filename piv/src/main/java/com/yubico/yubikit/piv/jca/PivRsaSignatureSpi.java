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
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
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
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class PivRsaSignatureSpi extends SignatureSpi {
  private final Callback<Callback<Result<PivSession, Exception>>> provider;
  private final Map<KeyType, KeyPair> dummyKeys;
  private final String signature;

  @Nullable private PivPrivateKey.RsaKey privateKey;

  @Nullable private Signature delegate;

  PivRsaSignatureSpi(
      Callback<Callback<Result<PivSession, Exception>>> provider,
      Map<KeyType, KeyPair> dummyKeys,
      String signature)
      throws NoSuchPaddingException {
    this.provider = provider;
    this.dummyKeys = dummyKeys;
    this.signature = signature;
  }

  private Signature getDelegate(boolean init) throws NoSuchAlgorithmException {
    if (delegate == null) {
      delegate = Signature.getInstance(signature);
      // If parameters are set before initSign is called we need to initialize the delegate to
      // choose Provider.
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
      return privateKey.rawSignOrDecrypt(provider, padded);
    } catch (Exception e) {
      throw new SignatureException(e);
    }
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    throw new SignatureException("Not initialized");
  }

  @SuppressWarnings("deprecation")
  @Override
  protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    try {
      //noinspection deprecation
      getDelegate(true).setParameter(param, value);
    } catch (NoSuchAlgorithmException e) {
      throw new InvalidParameterException("Not initialized");
    }
  }

  @SuppressWarnings("deprecation")
  @Override
  protected Object engineGetParameter(String param) throws InvalidParameterException {
    if (delegate != null) {
      //noinspection deprecation
      return delegate.getParameter(param);
    } else {
      throw new InvalidParameterException("Not initialized");
    }
  }

  @Override
  protected void engineSetParameter(AlgorithmParameterSpec params)
      throws InvalidAlgorithmParameterException {
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

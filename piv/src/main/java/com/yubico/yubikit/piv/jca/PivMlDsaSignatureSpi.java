/*
 * Copyright (C) 2026 Yubico.
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
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import org.jspecify.annotations.Nullable;

/**
 * Performs ML-DSA signatures (FIPS 204) using a private key stored in a YubiKey PIV slot.
 *
 * <p>The message is buffered and passed to the card as-is, since pure ML-DSA signing hashes the
 * message internally.
 */
public class PivMlDsaSignatureSpi extends SignatureSpi {
  private final Callback<Callback<Result<PivSession, Exception>>> provider;
  private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
  @Nullable private PivPrivateKey privateKey;

  PivMlDsaSignatureSpi(Callback<Callback<Result<PivSession, Exception>>> provider) {
    this.provider = provider;
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    throw new InvalidKeyException("Can only be used for signing.");
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    if (privateKey instanceof PivPrivateKey.MlDsaKey) {
      this.privateKey = (PivPrivateKey.MlDsaKey) privateKey;
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
      throw new SignatureException("Not initialized");
    }
  }

  @Override
  protected void engineUpdate(byte[] b, int off, int len) throws SignatureException {
    if (privateKey != null) {
      buffer.write(b, off, len);
    } else {
      throw new SignatureException("Not initialized");
    }
  }

  @Override
  protected byte[] engineSign() throws SignatureException {
    if (privateKey == null) {
      throw new SignatureException("Not initialized");
    }
    try {
      return privateKey.rawSignOrDecrypt(provider, buffer.toByteArray());
    } catch (Exception e) {
      throw new SignatureException(e);
    }
  }

  @Override
  protected boolean engineVerify(byte[] sigBytes) throws SignatureException {
    throw new SignatureException("Not initialized");
  }

  @Override
  @Deprecated
  protected void engineSetParameter(String param, Object value) throws InvalidParameterException {
    throw new InvalidParameterException("ML-DSA doesn't take parameters");
  }

  @Override
  @Deprecated
  protected Object engineGetParameter(String param) throws InvalidParameterException {
    throw new InvalidParameterException("ML-DSA doesn't take parameters");
  }
}

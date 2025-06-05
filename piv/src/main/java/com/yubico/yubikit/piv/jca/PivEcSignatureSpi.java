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

import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.piv.PivSession;
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
  private final Callback<Callback<Result<PivSession, Exception>>> provider;
  @Nullable private PivPrivateKey privateKey;

  protected PivEcSignatureSpi(Callback<Callback<Result<PivSession, Exception>>> provider) {
    this.provider = provider;
  }

  @Override
  protected void engineInitVerify(PublicKey publicKey) throws InvalidKeyException {
    throw new InvalidKeyException("Can only be used for signing.");
  }

  @Override
  protected void engineInitSign(PrivateKey privateKey) throws InvalidKeyException {
    if (privateKey instanceof PivPrivateKey.EcKey) {
      this.privateKey = (PivPrivateKey.EcKey) privateKey;
    } else if (privateKey instanceof PivPrivateKey.Ed25519Key) {
      this.privateKey = (PivPrivateKey.Ed25519Key) privateKey;
    } else if (privateKey instanceof PivPrivateKey.X25519Key) {
      this.privateKey = (PivPrivateKey.X25519Key) privateKey;
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
    try {
      return privateKey.rawSignOrDecrypt(provider, digest());
    } catch (Exception e) {
      throw new SignatureException(e);
    }
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

    Prehashed(Callback<Callback<Result<PivSession, Exception>>> provider) {
      super(provider);
    }

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

    Hashed(Callback<Callback<Result<PivSession, Exception>>> provider, String algorithm)
        throws NoSuchAlgorithmException {
      super(provider);
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

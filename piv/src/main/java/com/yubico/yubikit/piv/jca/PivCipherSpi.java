/*
 * Copyright (C) 2022-2023 Yubico.
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

import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Map;
import javax.annotation.Nullable;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import org.slf4j.LoggerFactory;

public class PivCipherSpi extends CipherSpi {
  private final Callback<Callback<Result<PivSession, Exception>>> provider;
  private final Map<KeyType, KeyPair> dummyKeys;
  private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
  @Nullable private PivPrivateKey privateKey;
  @Nullable private String mode;
  @Nullable private String padding;
  private int opmode = -1;

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(PivCipherSpi.class);

  PivCipherSpi(
      Callback<Callback<Result<PivSession, Exception>>> provider, Map<KeyType, KeyPair> dummyKeys)
      throws NoSuchPaddingException {
    this.provider = provider;
    this.dummyKeys = dummyKeys;
  }

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
  @Nullable
  protected AlgorithmParameters engineGetParameters() {
    return null;
  }

  @Override
  protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
    Logger.debug(logger, "Engine init: mode={} padding={}", mode, padding);
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
  protected void engineInit(
      int opmode, Key key, @Nullable AlgorithmParameterSpec params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (params != null) {
      throw new InvalidAlgorithmParameterException("Cipher must be initialized with params = null");
    }
    engineInit(opmode, key, random);
  }

  @Override
  protected void engineInit(
      int opmode, Key key, @Nullable AlgorithmParameters params, SecureRandom random)
      throws InvalidKeyException, InvalidAlgorithmParameterException {
    if (params != null) {
      throw new InvalidAlgorithmParameterException("Cipher must be initialized with params = null");
    }
    engineInit(opmode, key, random);
  }

  @Override
  protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
    buffer.write(input, inputOffset, inputLen);
    return new byte[0];
  }

  @Override
  protected int engineUpdate(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException {
    buffer.write(input, inputOffset, inputLen);
    return 0;
  }

  @Override
  protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
      throws IllegalBlockSizeException, BadPaddingException {
    if (privateKey == null) {
      throw new IllegalStateException("Cipher not initialized");
    }
    if (inputLen > 0) {
      buffer.write(input, inputOffset, inputLen);
    }
    byte[] cipherText = buffer.toByteArray();
    try {
      KeyPair dummy = dummyKeys.get(privateKey.keyType);
      Cipher rawRsa = Cipher.getInstance("RSA/ECB/NoPadding");
      rawRsa.init(opmode, dummy.getPublic());
      Cipher delegate = Cipher.getInstance("RSA/" + mode + "/" + padding);
      delegate.init(opmode, dummy.getPrivate());
      switch (opmode) {
        case Cipher.DECRYPT_MODE: // Decrypt, unpad
          return delegate.doFinal(
              rawRsa.doFinal(privateKey.rawSignOrDecrypt(provider, cipherText)));
        case Cipher.ENCRYPT_MODE: // Pad, decrypt
          try {
            return privateKey.rawSignOrDecrypt(
                provider, rawRsa.doFinal(delegate.doFinal(cipherText)));
          } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new IllegalStateException(e); // Shouldn't happen
          }
        default:
          throw new UnsupportedOperationException();
      }
    } catch (NoSuchPaddingException e) {
      throw new UnsupportedOperationException(
          "SecurityProvider doesn't support RSA without padding", e);
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
  }

  @Override
  protected int engineDoFinal(
      byte[] input, int inputOffset, int inputLen, byte[] output, int outputOffset)
      throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
    byte[] result = engineDoFinal(input, inputOffset, inputLen);
    try {
      System.arraycopy(result, 0, output, outputOffset, result.length);
      return result.length;
    } catch (IndexOutOfBoundsException e) {
      throw new ShortBufferException();
    }
  }
}

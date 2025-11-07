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

import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;
import com.yubico.yubikit.piv.VerificationPolicy;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import javax.annotation.Nullable;
import javax.security.auth.Destroyable;

public abstract class PivPrivateKey implements PrivateKey, Destroyable {
  final Slot slot;
  final KeyType keyType;
  @Nullable private final VerificationPolicy verificationPolicy;
  @Nullable private final TouchPolicy touchPolicy;
  @Nullable protected char[] pin;
  private boolean destroyed = false;

  static PivPrivateKey from(
      PublicKey publicKey,
      Slot slot,
      @Nullable VerificationPolicy verificationPolicy,
      @Nullable TouchPolicy touchPolicy,
      @Nullable char[] pin) {
    KeyType keyType = KeyType.fromKey(publicKey);
    if (keyType.params.algorithm == KeyType.Algorithm.RSA) {
      return new PivPrivateKey.RsaKey(
          slot,
          keyType,
          verificationPolicy,
          touchPolicy,
          ((RSAPublicKey) publicKey).getModulus(),
          pin);
    } else if (keyType == KeyType.ED25519) {
      return new PivPrivateKey.Ed25519Key(slot, keyType, verificationPolicy, touchPolicy, pin);
    } else if (keyType == KeyType.X25519) {
      return new PivPrivateKey.X25519Key(slot, keyType, verificationPolicy, touchPolicy, pin);
    } else {
      return new PivPrivateKey.EcKey(
          slot,
          keyType,
          verificationPolicy,
          touchPolicy,
          ((ECPublicKey) publicKey).getParams(),
          pin);
    }
  }

  protected PivPrivateKey(
      Slot slot,
      KeyType keyType,
      @Nullable VerificationPolicy verificationPolicy,
      @Nullable TouchPolicy touchPolicy,
      @Nullable char[] pin) {
    this.slot = slot;
    this.keyType = keyType;
    this.verificationPolicy = verificationPolicy;
    this.touchPolicy = touchPolicy;
    this.pin = pin != null ? Arrays.copyOf(pin, pin.length) : null;
  }

  byte[] rawSignOrDecrypt(
      Callback<Callback<Result<PivSession, Exception>>> provider, byte[] payload) throws Exception {
    if (destroyed) {
      throw new IllegalStateException("PivPrivateKey has been destroyed");
    }
    BlockingQueue<Result<byte[], Exception>> queue = new ArrayBlockingQueue<>(1);
    provider.invoke(
        result ->
            queue.add(
                Result.of(
                    () -> {
                      PivSession session = result.getValue();
                      if (pin != null) {
                        session.verifyPin(pin);
                      }
                      return session.rawSignOrDecrypt(slot, keyType, payload);
                    })));
    return queue.take().getValue();
  }

  /** Get the PIV slot where the private key is stored. */
  public Slot getSlot() {
    return slot;
  }

  /** Get the PIN policy of the key, if available. */
  @Nullable
  public VerificationPolicy getVerificationPolicy() {
    return verificationPolicy;
  }

  /** Get the Touch policy of the key, if available. */
  @Nullable
  public TouchPolicy getTouchPolicy() {
    return touchPolicy;
  }

  /**
   * Sets the PIN to use when performing key operations with this private key, or to null. Note that
   * a copy is made of the PIN, which can be cleared out by calling {@link #destroy()}.
   */
  public void setPin(@Nullable char[] pin) {
    if (destroyed) {
      throw new IllegalStateException("PivPrivateKey has been destroyed");
    }
    // Zero out the old PIN, if one was set
    if (this.pin != null) {
      Arrays.fill(this.pin, (char) 0);
    }
    this.pin = pin != null ? Arrays.copyOf(pin, pin.length) : null;
  }

  @Override
  public void destroy() {
    if (pin != null) {
      Arrays.fill(pin, (char) 0);
    }
    destroyed = true;
  }

  @Override
  public boolean isDestroyed() {
    return destroyed;
  }

  @Override
  public String getAlgorithm() {
    return keyType.params.algorithm.name();
  }

  @Override
  @Nullable
  public String getFormat() {
    return null;
  }

  @Override
  @Nullable
  public byte[] getEncoded() {
    return null;
  }

  static class EcKey extends PivPrivateKey implements ECKey {
    private final ECParameterSpec ecSpec;

    private EcKey(
        Slot slot,
        KeyType keyType,
        @Nullable VerificationPolicy verificationPolicy,
        @Nullable TouchPolicy touchPolicy,
        ECParameterSpec ecSpec,
        @Nullable char[] pin) {
      super(slot, keyType, verificationPolicy, touchPolicy, pin);
      this.ecSpec = ecSpec;
    }

    byte[] keyAgreement(
        Callback<Callback<Result<PivSession, Exception>>> provider,
        PublicKeyValues peerPublicKeyValues)
        throws Exception {
      BlockingQueue<Result<byte[], Exception>> queue = new ArrayBlockingQueue<>(1);
      provider.invoke(
          result ->
              queue.add(
                  Result.of(
                      () -> {
                        PivSession session = result.getValue();
                        if (pin != null) {
                          session.verifyPin(pin);
                        }
                        return session.calculateSecret(slot, peerPublicKeyValues);
                      })));
      return queue.take().getValue();
    }

    @Override
    public ECParameterSpec getParams() {
      return ecSpec;
    }
  }

  static class RsaKey extends PivPrivateKey implements RSAKey {
    private final BigInteger modulus;

    private RsaKey(
        Slot slot,
        KeyType keyType,
        @Nullable VerificationPolicy verificationPolicy,
        @Nullable TouchPolicy touchPolicy,
        BigInteger modulus,
        @Nullable char[] pin) {
      super(slot, keyType, verificationPolicy, touchPolicy, pin);
      this.modulus = modulus;
    }

    @Override
    public BigInteger getModulus() {
      return modulus;
    }
  }

  static class Ed25519Key extends PivPrivateKey implements PrivateKey {
    private Ed25519Key(
        Slot slot,
        KeyType keyType,
        @Nullable VerificationPolicy verificationPolicy,
        @Nullable TouchPolicy touchPolicy,
        @Nullable char[] pin) {
      super(slot, keyType, verificationPolicy, touchPolicy, pin);
    }
  }

  static class X25519Key extends PivPrivateKey implements PrivateKey {
    private X25519Key(
        Slot slot,
        KeyType keyType,
        @Nullable VerificationPolicy verificationPolicy,
        @Nullable TouchPolicy touchPolicy,
        @Nullable char[] pin) {
      super(slot, keyType, verificationPolicy, touchPolicy, pin);
    }

    byte[] keyAgreement(
        Callback<Callback<Result<PivSession, Exception>>> provider,
        PublicKeyValues peerPublicKeyValues)
        throws Exception {
      BlockingQueue<Result<byte[], Exception>> queue = new ArrayBlockingQueue<>(1);
      provider.invoke(
          result ->
              queue.add(
                  Result.of(
                      () -> {
                        PivSession session = result.getValue();
                        if (pin != null) {
                          session.verifyPin(pin);
                        }
                        return session.calculateSecret(slot, peerPublicKeyValues);
                      })));
      return queue.take().getValue();
    }
  }
}

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

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.SlotMetadata;
import com.yubico.yubikit.piv.TouchPolicy;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import javax.annotation.Nullable;

public class PivKeyStoreSpi extends KeyStoreSpi {
  private final Callback<Callback<Result<PivSession, Exception>>> provider;

  PivKeyStoreSpi(Callback<Callback<Result<PivSession, Exception>>> provider) {
    this.provider = provider;
  }

  private void putEntry(
      Slot slot,
      @Nullable PrivateKey key,
      PinPolicy pinPolicy,
      TouchPolicy touchPolicy,
      @Nullable X509Certificate certificate)
      throws Exception {
    BlockingQueue<Result<Boolean, Exception>> queue = new ArrayBlockingQueue<>(1);
    provider.invoke(
        result ->
            queue.add(
                Result.of(
                    () -> {
                      PivSession piv = result.getValue();
                      if (key != null) {
                        piv.putKey(
                            slot, PrivateKeyValues.fromPrivateKey(key), pinPolicy, touchPolicy);
                      }
                      if (certificate != null) {
                        piv.putCertificate(slot, certificate);
                      }
                      return true;
                    })));
    queue.take().getValue();
  }

  @Override
  @Nullable
  public Key engineGetKey(String alias, char[] password) throws UnrecoverableKeyException {
    Slot slot = Slot.fromStringAlias(alias);
    try {
      BlockingQueue<Result<PivPrivateKey, Exception>> queue = new ArrayBlockingQueue<>(1);
      provider.invoke(
          result ->
              queue.add(
                  Result.of(
                      () -> {
                        PivSession session = result.getValue();
                        if (session.supports(PivSession.FEATURE_METADATA)) {
                          SlotMetadata data = session.getSlotMetadata(slot);
                          return PivPrivateKey.from(
                              data.getPublicKeyValues().toPublicKey(),
                              slot,
                              data.getPinPolicy(),
                              data.getTouchPolicy(),
                              password);
                        } else {
                          PublicKey publicKey = session.getCertificate(slot).getPublicKey();
                          return PivPrivateKey.from(publicKey, slot, null, null, password);
                        }
                      })));
      return queue.take().getValue();
    } catch (BadResponseException e) {
      throw new UnrecoverableKeyException(
          "No way to infer KeyType, make sure the matching certificate is stored");
    } catch (ApduException e) {
      if (e.getSw() == SW.FILE_NOT_FOUND) {
        return null;
      }
      throw new RuntimeException(e);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  public Certificate[] engineGetCertificateChain(String alias) {
    return new Certificate[] {engineGetCertificate(alias)};
  }

  @Override
  @Nullable
  public Certificate engineGetCertificate(String alias) {
    Slot slot = Slot.fromStringAlias(alias);
    BlockingQueue<Result<X509Certificate, Exception>> queue = new ArrayBlockingQueue<>(1);
    provider.invoke(result -> queue.add(Result.of(() -> result.getValue().getCertificate(slot))));

    try {
      return queue.take().getValue();
    } catch (BadResponseException e) {
      // Malformed certificate?
      return null;
    } catch (ApduException e) {
      if (e.getSw() == SW.FILE_NOT_FOUND) {
        // Empty slot
        return null;
      }
      throw new RuntimeException(e);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  @Nullable
  public KeyStore.Entry engineGetEntry(String alias, KeyStore.ProtectionParameter protParam)
      throws UnrecoverableEntryException {
    Slot slot = Slot.fromStringAlias(alias);
    try {
      BlockingQueue<Result<KeyStore.Entry, Exception>> queue = new ArrayBlockingQueue<>(1);
      provider.invoke(
          result ->
              queue.add(
                  Result.of(
                      () -> {
                        PivSession session = result.getValue();
                        Certificate certificate = session.getCertificate(slot);
                        char[] pin = null;
                        if (protParam instanceof KeyStore.PasswordProtection) {
                          pin = ((KeyStore.PasswordProtection) protParam).getPassword();
                        }
                        PrivateKey key;
                        if (session.supports(PivSession.FEATURE_METADATA)) {
                          SlotMetadata data = session.getSlotMetadata(slot);
                          key =
                              PivPrivateKey.from(
                                  data.getPublicKeyValues().toPublicKey(),
                                  slot,
                                  data.getPinPolicy(),
                                  data.getTouchPolicy(),
                                  pin);
                        } else {
                          PublicKey publicKey = certificate.getPublicKey();
                          key = PivPrivateKey.from(publicKey, slot, null, null, pin);
                        }
                        return new KeyStore.PrivateKeyEntry(key, new Certificate[] {certificate});
                      })));
      return queue.take().getValue();
    } catch (BadResponseException e) {
      throw new UnrecoverableEntryException("Make sure the matching certificate is stored");
    } catch (ApduException e) {
      if (e.getSw() == SW.FILE_NOT_FOUND) {
        // Empty slot
        return null;
      }
      throw new RuntimeException(e);
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
  }

  @Override
  @Nullable
  public Date engineGetCreationDate(String alias) {
    return null;
  }

  @Override
  public void engineSetEntry(
      String alias, KeyStore.Entry entry, @Nullable KeyStore.ProtectionParameter protParam)
      throws KeyStoreException {
    Slot slot = Slot.fromStringAlias(alias);

    PrivateKey privateKey = null;
    Certificate certificate;
    if (entry instanceof KeyStore.TrustedCertificateEntry) {
      if (protParam != null) {
        throw new KeyStoreException("Certificate cannot use protParam");
      }
      certificate = ((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate();
    } else if (entry instanceof KeyStore.PrivateKeyEntry) {
      certificate = ((KeyStore.PrivateKeyEntry) entry).getCertificate();
      privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
    } else {
      throw new KeyStoreException("Unsupported KeyStore entry.");
    }

    if (certificate != null) {
      if (!(certificate instanceof X509Certificate)) {
        throw new KeyStoreException("Certificate must be X509Certificate");
      }
    }

    PinPolicy pinPolicy = PinPolicy.DEFAULT;
    TouchPolicy touchPolicy = TouchPolicy.DEFAULT;
    if (privateKey != null) {
      if (protParam != null) {
        if (protParam instanceof PivKeyStoreKeyParameters) {
          pinPolicy = ((PivKeyStoreKeyParameters) protParam).pinPolicy;
          touchPolicy = ((PivKeyStoreKeyParameters) protParam).touchPolicy;
        } else {
          throw new KeyStoreException("protParam must be an instance of PivKeyStoreKeyParameters");
        }
      }
    }

    try {
      putEntry(slot, privateKey, pinPolicy, touchPolicy, (X509Certificate) certificate);
    } catch (Exception e) {
      throw new KeyStoreException(e);
    }
  }

  @Override
  public void engineSetKeyEntry(
      String alias, Key key, @Nullable char[] password, Certificate[] chain)
      throws KeyStoreException {
    Slot slot = Slot.fromStringAlias(alias);

    if (password != null) {
      throw new KeyStoreException("Password can not be set");
    }

    if (chain.length != 1) {
      throw new KeyStoreException("Certificate chain must be a single certificate, or empty");
    }
    if (chain[0] instanceof X509Certificate) {
      try {
        putEntry(
            slot,
            (PrivateKey) key,
            PinPolicy.DEFAULT,
            TouchPolicy.DEFAULT,
            (X509Certificate) chain[0]);
      } catch (Exception e) {
        throw new KeyStoreException(e);
      }
    } else {
      throw new KeyStoreException("Certificate must be X509Certificate");
    }
  }

  @Override
  public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain)
      throws KeyStoreException {
    throw new KeyStoreException("Use setKeyEntry with a PrivateKey instance instead of byte[]");
  }

  @Override
  public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
    Slot slot = Slot.fromStringAlias(alias);
    if (cert instanceof X509Certificate) {
      try {
        putEntry(slot, null, PinPolicy.DEFAULT, TouchPolicy.DEFAULT, (X509Certificate) cert);
      } catch (Exception e) {
        throw new KeyStoreException(e);
      }
    } else {
      throw new KeyStoreException("Certificate must be X509Certificate");
    }
  }

  @Override
  public void engineDeleteEntry(String alias) throws KeyStoreException {
    Slot slot = Slot.fromStringAlias(alias);

    BlockingQueue<Result<Boolean, Exception>> queue = new ArrayBlockingQueue<>(1);
    provider.invoke(
        result ->
            queue.add(
                Result.of(
                    () -> {
                      result.getValue().deleteCertificate(slot);
                      return true;
                    })));

    try {
      queue.take().getValue();
    } catch (Exception e) {
      throw new KeyStoreException(e);
    }
  }

  @Override
  public Enumeration<String> engineAliases() {
    throw new UnsupportedOperationException();
  }

  @Override
  public boolean engineContainsAlias(String alias) {
    try {
      Slot.fromStringAlias(alias);
      return true;
    } catch (IllegalArgumentException e) {
      return false;
    }
  }

  @Override
  public int engineSize() {
    return Slot.values().length;
  }

  @Override
  public boolean engineIsKeyEntry(String alias) {
    return engineContainsAlias(alias);
  }

  @Override
  public boolean engineIsCertificateEntry(String alias) {
    return engineGetCertificate(alias) != null;
  }

  @Override
  @Nullable
  public String engineGetCertificateAlias(Certificate cert) {
    for (Slot slot : Slot.values()) {
      String alias = slot.getStringAlias();
      if (cert.equals(engineGetCertificate(alias))) {
        return alias;
      }
    }
    return null;
  }

  @Override
  public void engineStore(OutputStream stream, char[] password) {
    throw new UnsupportedOperationException();
  }

  @Override
  public void engineLoad(InputStream stream, char[] password) {
    throw new InvalidParameterException("KeyStore must be loaded with a null LoadStoreParameter");
  }

  @Override
  public void engineLoad(@Nullable KeyStore.LoadStoreParameter param) {
    if (param != null) {
      throw new InvalidParameterException("KeyStore must be loaded with null");
    }
  }
}

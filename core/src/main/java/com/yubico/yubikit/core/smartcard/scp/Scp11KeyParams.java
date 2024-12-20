/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.core.smartcard.scp;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nullable;

/**
 * SCP key parameters for performing SCP11 authentication.
 *
 * <p>For SCP11b only keyRef and pkSdEcka are required. Note that this does not authenticate the
 * off-card entity.
 *
 * <p>For SCP11a and SCP11c the off-card entity CA key reference must be provided, as well as the
 * off-card entity secret key and certificate chain.
 */
public class Scp11KeyParams implements ScpKeyParams {
  private final KeyRef keyRef;
  final PublicKey pkSdEcka;
  @Nullable final KeyRef oceKeyRef;
  @Nullable final PrivateKey skOceEcka;
  final List<X509Certificate> certificates;

  public Scp11KeyParams(
      KeyRef keyRef,
      PublicKey pkSdEcka,
      @Nullable KeyRef oceKeyRef,
      @Nullable PrivateKey skOceEcka,
      List<X509Certificate> certificates) {
    this.keyRef = keyRef;
    this.pkSdEcka = pkSdEcka;
    this.oceKeyRef = oceKeyRef;
    this.skOceEcka = skOceEcka;
    this.certificates = Collections.unmodifiableList(new ArrayList<>(certificates));
    switch (keyRef.getKid()) {
      case ScpKid.SCP11b:
        if (oceKeyRef != null || skOceEcka != null || !certificates.isEmpty()) {
          throw new IllegalArgumentException(
              "Cannot provide oceKeyRef, skOceEcka or certificates for SCP11b");
        }
        break;
      case ScpKid.SCP11a:
      case ScpKid.SCP11c:
        if (oceKeyRef == null || skOceEcka == null || certificates.isEmpty()) {
          throw new IllegalArgumentException(
              "Must provide oceKeyRef, skOceEcka or certificates for SCP11a/c");
        }
        break;
      default:
        throw new IllegalArgumentException("KID must be 0x11, 0x13, or 0x15 for SCP11");
    }
  }

  public Scp11KeyParams(KeyRef keyRef, PublicKey pkSdEcka) {
    this(keyRef, pkSdEcka, null, null, Collections.emptyList());
  }

  @Override
  public KeyRef getKeyRef() {
    return keyRef;
  }
}

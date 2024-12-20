/*
 * Copyright (C) 2023 Yubico.
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

package com.yubico.yubikit.fido;

import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.core.keys.EllipticCurveValues;
import com.yubico.yubikit.core.keys.PublicKeyValues.Cv25519;
import com.yubico.yubikit.core.keys.PublicKeyValues.Ec;
import com.yubico.yubikit.core.keys.PublicKeyValues.Rsa;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

public class Cose {

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Cose.class);

  public static Integer getAlgorithm(Map<Integer, ?> cosePublicKey) {
    Integer alg = (Integer) Objects.requireNonNull(cosePublicKey.get(3));
    Logger.debug(logger, "alg: {}", alg);
    return alg;
  }

  @Nullable
  public static PublicKey getPublicKey(@Nullable Map<Integer, ?> cosePublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException {

    if (cosePublicKey == null) {
      return null;
    }

    final Integer kty = (Integer) Objects.requireNonNull(cosePublicKey.get(1));
    Logger.debug(logger, "kty: {}", kty);
    PublicKey publicKey;
    switch (kty) {
      case 1:
        publicKey = importCoseEdDsaPublicKey(cosePublicKey);
        break;
      case 2:
        publicKey = importCoseEcdsaPublicKey(cosePublicKey);
        break;
      case 3:
        publicKey = importCoseRsaPublicKey(cosePublicKey);
        break;
      default:
        throw new IllegalArgumentException("Unsupported key type: " + kty);
    }

    Logger.debug(logger, "publicKey: {}", Base64.toUrlSafeString(publicKey.getEncoded()));

    return publicKey;
  }

  private static PublicKey importCoseEdDsaPublicKey(Map<Integer, ?> cosePublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    final Integer crv = (Integer) Objects.requireNonNull(cosePublicKey.get(-1));
    Logger.debug(logger, "crv: {}", crv);
    if (crv == 6) {
      return importCoseEd25519PublicKey(cosePublicKey);
    }
    throw new IllegalArgumentException("Unsupported EdDSA curve: " + crv);
  }

  private static PublicKey importCoseEd25519PublicKey(Map<Integer, ?> cosePublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    final byte[] rawKey = (byte[]) Objects.requireNonNull(cosePublicKey.get(-2));
    Logger.debug(logger, "raw: {}", Base64.toUrlSafeString(rawKey));
    return new Cv25519(EllipticCurveValues.Ed25519, rawKey).toPublicKey();
  }

  private static PublicKey importCoseEcdsaPublicKey(Map<Integer, ?> cosePublicKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    final Integer crv = (Integer) Objects.requireNonNull(cosePublicKey.get(-1));
    final byte[] x = (byte[]) Objects.requireNonNull(cosePublicKey.get(-2));
    final byte[] y = (byte[]) Objects.requireNonNull(cosePublicKey.get(-3));

    Logger.debug(logger, "crv: {}", crv);
    Logger.debug(logger, "x: {}", Base64.toUrlSafeString(x));
    Logger.debug(logger, "y: {}", Base64.toUrlSafeString(y));

    EllipticCurveValues ellipticCurveValues;

    switch (crv) {
      case 1:
        ellipticCurveValues = EllipticCurveValues.SECP256R1;
        break;

      case 2:
        ellipticCurveValues = EllipticCurveValues.SECP384R1;
        break;

      case 3:
        ellipticCurveValues = EllipticCurveValues.SECP521R1;
        break;

      default:
        throw new IllegalArgumentException("Unknown COSE EC2 curve: " + crv);
    }

    return new Ec(ellipticCurveValues, new BigInteger(x), new BigInteger(y)).toPublicKey();
  }

  private static PublicKey importCoseRsaPublicKey(Map<Integer, ?> cosePublicKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] n = (byte[]) Objects.requireNonNull(cosePublicKey.get(-1));
    byte[] e = (byte[]) Objects.requireNonNull(cosePublicKey.get(-2));
    Logger.debug(logger, "n: {}", Base64.toUrlSafeString(n));
    Logger.debug(logger, "e: {}", Base64.toUrlSafeString(e));
    return new Rsa(new BigInteger(1, n), new BigInteger(1, e)).toPublicKey();
  }
}

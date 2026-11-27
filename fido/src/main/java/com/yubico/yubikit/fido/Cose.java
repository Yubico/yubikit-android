/*
 * Copyright (C) 2023-2026 Yubico.
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

import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.core.keys.EllipticCurveValues;
import com.yubico.yubikit.core.keys.MlDsaParameterValues;
import com.yubico.yubikit.core.keys.PublicKeyValues.Cv25519;
import com.yubico.yubikit.core.keys.PublicKeyValues.Ec;
import com.yubico.yubikit.core.keys.PublicKeyValues.MlDsa;
import com.yubico.yubikit.core.keys.PublicKeyValues.Rsa;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Cose {

  private static final Logger logger = LoggerFactory.getLogger(Cose.class);

  /**
   * COSE key types.
   *
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#key-type">COSE Key Types</a>
   */
  private static final class KeyType {
    static final int OKP = 1;
    static final int EC2 = 2;
    static final int RSA = 3;
    static final int AKP = 7;
  }

  /**
   * COSE algorithm identifiers.
   *
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms</a>
   */
  private static final class Algorithm {
    static final int EDDSA = -8;
    static final int ED25519 = -19;
    static final int ED448 = -53;
    static final int ES256 = -7;
    static final int ES384 = -35;
    static final int ES512 = -36;
    static final int RS256 = -257;
    static final int RS384 = -258;
    static final int RS512 = -259;
    static final int RS1 = -65535;
    static final int PS256 = -37;
    static final int PS384 = -38;
    static final int PS512 = -39;
    static final int ML_DSA_44 = -48;
    static final int ML_DSA_65 = -49;
    static final int ML_DSA_87 = -50;
  }

  /**
   * The COSE key type that each known algorithm requires. Algorithms that are not listed are not
   * checked.
   *
   * @see <a href="https://www.iana.org/assignments/cose/cose.xhtml#algorithms">COSE Algorithms</a>
   */
  private static final Map<Integer, Integer> KEY_TYPE_BY_ALGORITHM;

  static {
    Map<Integer, Integer> keyTypes = new HashMap<>();
    for (int alg : new int[] {Algorithm.EDDSA, Algorithm.ED25519, Algorithm.ED448}) {
      keyTypes.put(alg, KeyType.OKP);
    }
    for (int alg : new int[] {Algorithm.ES256, Algorithm.ES384, Algorithm.ES512}) {
      keyTypes.put(alg, KeyType.EC2);
    }
    for (int alg :
        new int[] {
          Algorithm.RS256,
          Algorithm.RS384,
          Algorithm.RS512,
          Algorithm.RS1,
          Algorithm.PS256,
          Algorithm.PS384,
          Algorithm.PS512
        }) {
      keyTypes.put(alg, KeyType.RSA);
    }
    for (int alg : new int[] {Algorithm.ML_DSA_44, Algorithm.ML_DSA_65, Algorithm.ML_DSA_87}) {
      keyTypes.put(alg, KeyType.AKP);
    }
    KEY_TYPE_BY_ALGORITHM = Collections.unmodifiableMap(keyTypes);
  }

  public static Integer getAlgorithm(Map<Integer, ?> cosePublicKey) {
    Integer alg = (Integer) Objects.requireNonNull(cosePublicKey.get(3));
    logger.debug("alg: {}", alg);
    return alg;
  }

  @Nullable
  public static PublicKey getPublicKey(@Nullable Map<Integer, ?> cosePublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException {

    if (cosePublicKey == null) {
      return null;
    }

    final Integer kty = (Integer) Objects.requireNonNull(cosePublicKey.get(1));
    logger.debug("kty: {}", kty);
    Object alg = cosePublicKey.get(3);
    Integer expectedKty = KEY_TYPE_BY_ALGORITHM.get(alg);
    if (expectedKty != null && !expectedKty.equals(kty)) {
      throw new IllegalArgumentException(
          "COSE key type " + kty + " does not match algorithm " + alg);
    }
    PublicKey publicKey;
    switch (kty) {
      case KeyType.OKP:
        publicKey = importCoseEdDsaPublicKey(cosePublicKey);
        break;
      case KeyType.EC2:
        publicKey = importCoseEcdsaPublicKey(cosePublicKey);
        break;
      case KeyType.RSA:
        publicKey = importCoseRsaPublicKey(cosePublicKey);
        break;
      case KeyType.AKP:
        publicKey = importCoseAkpPublicKey(cosePublicKey);
        break;
      default:
        throw new IllegalArgumentException("Unsupported key type: " + kty);
    }

    if (logger.isDebugEnabled()) {
      logger.debug("publicKey: {}", Base64.toUrlSafeString(publicKey.getEncoded()));
    }

    return publicKey;
  }

  private static PublicKey importCoseEdDsaPublicKey(Map<Integer, ?> cosePublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    final Integer crv = (Integer) Objects.requireNonNull(cosePublicKey.get(-1));
    logger.debug("crv: {}", crv);
    if (crv == 6) {
      return importCoseEd25519PublicKey(cosePublicKey);
    }
    throw new IllegalArgumentException("Unsupported EdDSA curve: " + crv);
  }

  private static PublicKey importCoseEd25519PublicKey(Map<Integer, ?> cosePublicKey)
      throws InvalidKeySpecException, NoSuchAlgorithmException {
    final byte[] rawKey = (byte[]) Objects.requireNonNull(cosePublicKey.get(-2));
    if (logger.isDebugEnabled()) {
      logger.debug("raw: {}", Base64.toUrlSafeString(rawKey));
    }
    return new Cv25519(EllipticCurveValues.Ed25519, rawKey).toPublicKey();
  }

  private static PublicKey importCoseEcdsaPublicKey(Map<Integer, ?> cosePublicKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    final Integer crv = (Integer) Objects.requireNonNull(cosePublicKey.get(-1));
    final byte[] x = (byte[]) Objects.requireNonNull(cosePublicKey.get(-2));
    final byte[] y = (byte[]) Objects.requireNonNull(cosePublicKey.get(-3));

    logger.debug("crv: {}", crv);
    if (logger.isDebugEnabled()) {
      logger.debug("x: {}", Base64.toUrlSafeString(x));
      logger.debug("y: {}", Base64.toUrlSafeString(y));
    }

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

    // Parse coordinates as unsigned big-endian integers (RFC 9053 7.1.1) to avoid sign-extension
    // byte truncation.
    return new Ec(ellipticCurveValues, new BigInteger(1, x), new BigInteger(1, y)).toPublicKey();
  }

  private static PublicKey importCoseRsaPublicKey(Map<Integer, ?> cosePublicKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    byte[] n = (byte[]) Objects.requireNonNull(cosePublicKey.get(-1));
    byte[] e = (byte[]) Objects.requireNonNull(cosePublicKey.get(-2));
    if (logger.isDebugEnabled()) {
      logger.debug("n: {}", Base64.toUrlSafeString(n));
      logger.debug("e: {}", Base64.toUrlSafeString(e));
    }
    return new Rsa(new BigInteger(1, n), new BigInteger(1, e)).toPublicKey();
  }

  private static PublicKey importCoseAkpPublicKey(Map<Integer, ?> cosePublicKey)
      throws NoSuchAlgorithmException, InvalidKeySpecException {
    final Integer alg = (Integer) Objects.requireNonNull(cosePublicKey.get(3));
    final byte[] pub = (byte[]) Objects.requireNonNull(cosePublicKey.get(-1));
    logger.debug("alg: {}", alg);
    if (logger.isDebugEnabled()) {
      logger.debug("pub: {}", Base64.toUrlSafeString(pub));
    }

    MlDsaParameterValues parameterValues;
    switch (alg) {
      case Algorithm.ML_DSA_44:
        parameterValues = MlDsaParameterValues.MLDSA_44;
        break;
      case Algorithm.ML_DSA_65:
        parameterValues = MlDsaParameterValues.MLDSA_65;
        break;
      case Algorithm.ML_DSA_87:
        parameterValues = MlDsaParameterValues.MLDSA_87;
        break;
      default:
        throw new IllegalArgumentException("Unsupported AKP algorithm: " + alg);
    }

    return new MlDsa(parameterValues, pub).toPublicKey();
  }
}

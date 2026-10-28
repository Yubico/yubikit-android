/*
 * Copyright (C) 2019-2022,2024,2026 Yubico.
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

package com.yubico.yubikit.piv;

import com.yubico.yubikit.core.keys.EllipticCurveValues;
import com.yubico.yubikit.core.keys.MlDsaParameterValues;
import com.yubico.yubikit.core.keys.MlKemParameterValues;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAKey;

/** Supported private key types for use with the PIV YubiKey application. */
public enum KeyType {
  /** RSA with a 1024 bit key. */
  RSA1024((byte) 0x06, new RsaKeyParams(1024)),

  /** RSA with a 2048 bit key. */
  RSA2048((byte) 0x07, new RsaKeyParams(2048)),

  /** RSA with a 3072 bit key. */
  RSA3072((byte) 0x05, new RsaKeyParams(3072)),

  /** RSA with a 4096 bit key. */
  RSA4096((byte) 0x16, new RsaKeyParams(4096)),

  /** Elliptic Curve key, using NIST Curve P-256. */
  ECCP256((byte) 0x11, new EcKeyParams(EllipticCurveValues.SECP256R1)),
  /** Elliptic Curve key, using NIST Curve P-384. */
  ECCP384((byte) 0x14, new EcKeyParams(EllipticCurveValues.SECP384R1)),
  /** Edwards Digital Signature Algorithm (EdDSA) key, using Curve25519. */
  ED25519((byte) 0xE0, new EcKeyParams(EllipticCurveValues.Ed25519)),
  /** Elliptic-Curve Diffie-Hellman (ECDH) protocol key, using Curve25519. */
  X25519((byte) 0xE1, new EcKeyParams(EllipticCurveValues.X25519)),
  /** Module-Lattice-Based Digital Signature Algorithm (ML-DSA) key, parameter set 44. */
  MLDSA44((byte) 0xE2, new MlDsaKeyParams(MlDsaParameterValues.MLDSA_44)),
  /** Module-Lattice-Based Digital Signature Algorithm (ML-DSA) key, parameter set 65. */
  MLDSA65((byte) 0xE3, new MlDsaKeyParams(MlDsaParameterValues.MLDSA_65)),
  /** Module-Lattice-Based Digital Signature Algorithm (ML-DSA) key, parameter set 87. */
  MLDSA87((byte) 0xE4, new MlDsaKeyParams(MlDsaParameterValues.MLDSA_87)),
  /** Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) key, parameter set 512. */
  MLKEM512((byte) 0xE5, new MlKemKeyParams(MlKemParameterValues.MLKEM_512)),
  /** Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) key, parameter set 768. */
  MLKEM768((byte) 0xE6, new MlKemKeyParams(MlKemParameterValues.MLKEM_768)),
  /** Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM) key, parameter set 1024. */
  MLKEM1024((byte) 0xE7, new MlKemKeyParams(MlKemParameterValues.MLKEM_1024));

  private static final int NO_BIT_LENGTH = 0;

  public final byte value;
  public final KeyParams params;

  KeyType(byte value, KeyParams params) {
    this.value = value;
    this.params = params;
  }

  /**
   * Returns the key type corresponding to the given PIV algorithm constant, given either as a byte
   * or as an unsigned value.
   */
  public static KeyType fromValue(int value) {
    for (KeyType type : KeyType.values()) {
      if ((type.value & 0xFF) == (value & 0xFF)) {
        return type;
      }
    }
    throw new IllegalArgumentException("Not a valid KeyType:" + value);
  }

  public static KeyType fromKeyParams(PrivateKeyValues keyValues) {
    if (keyValues instanceof PrivateKeyValues.Rsa) {
      for (KeyType keyType : values()) {
        if (keyType.params instanceof KeyType.RsaKeyParams) {
          if (keyValues.getBitLength() == keyType.params.bitLength) {
            return keyType;
          }
        }
      }
    } else if (keyValues instanceof PrivateKeyValues.Ec) {
      return fromEllipticCurveValues(((PrivateKeyValues.Ec) keyValues).getCurveParams());
    } else if (keyValues instanceof PrivateKeyValues.MlDsa) {
      return fromMlDsaParameterValues(((PrivateKeyValues.MlDsa) keyValues).getParameterValues());
    } else if (keyValues instanceof PrivateKeyValues.MlKem) {
      return fromMlKemParameterValues(((PrivateKeyValues.MlKem) keyValues).getParameterValues());
    }
    throw new IllegalArgumentException("Unsupported key type");
  }

  /** Returns the key type corresponding to the given key. */
  public static KeyType fromKey(Key key) {
    if (key instanceof RSAKey) {
      for (KeyType keyType : values()) {
        if (keyType.params.algorithm == Algorithm.RSA
            && keyType.params.bitLength == ((RSAKey) key).getModulus().bitLength()) {
          return keyType;
        }
      }
    } else if (key instanceof PublicKey) {
      PublicKeyValues publicKeyValues = PublicKeyValues.fromPublicKey((PublicKey) key);
      if (publicKeyValues instanceof PublicKeyValues.Ec) {
        return fromEllipticCurveValues(((PublicKeyValues.Ec) publicKeyValues).getCurveParams());
      } else if (publicKeyValues instanceof PublicKeyValues.Cv25519) {
        return fromEllipticCurveValues(
            ((PublicKeyValues.Cv25519) publicKeyValues).getCurveParams());
      } else if (publicKeyValues instanceof PublicKeyValues.MlDsa) {
        return fromMlDsaParameterValues(
            ((PublicKeyValues.MlDsa) publicKeyValues).getParameterValues());
      } else if (publicKeyValues instanceof PublicKeyValues.MlKem) {
        return fromMlKemParameterValues(
            ((PublicKeyValues.MlKem) publicKeyValues).getParameterValues());
      }
      throw new IllegalArgumentException("Unsupported public key type");
    } else if (key instanceof PrivateKey) {
      return fromKeyParams(PrivateKeyValues.fromPrivateKey((PrivateKey) key));
    }
    throw new IllegalArgumentException("Unsupported key type");
  }

  private static KeyType fromEllipticCurveValues(EllipticCurveValues ellipticCurveValues) {
    for (KeyType keyType : values()) {
      if (keyType.params instanceof KeyType.EcKeyParams
          && ((EcKeyParams) keyType.params).ellipticCurveValues == ellipticCurveValues) {
        return keyType;
      }
    }
    throw new IllegalArgumentException("Unsupported key type");
  }

  private static KeyType fromMlDsaParameterValues(MlDsaParameterValues parameterValues) {
    for (KeyType keyType : values()) {
      if (keyType.params instanceof MlDsaKeyParams
          && ((MlDsaKeyParams) keyType.params).parameterValues == parameterValues) {
        return keyType;
      }
    }
    throw new IllegalArgumentException("Unsupported key type");
  }

  private static KeyType fromMlKemParameterValues(MlKemParameterValues parameterValues) {
    for (KeyType keyType : values()) {
      if (keyType.params instanceof MlKemKeyParams
          && ((MlKemKeyParams) keyType.params).parameterValues == parameterValues) {
        return keyType;
      }
    }
    throw new IllegalArgumentException("Unsupported key type");
  }

  /** Key algorithm identifier. */
  public enum Algorithm {
    RSA,
    EC,
    MLDSA,
    MLKEM
  }

  /**
   * Algorithm parameters used by a KeyType.
   *
   * <p>The bit length is 0 for ML-DSA and ML-KEM keys, which are not measured in bits.
   */
  public abstract static class KeyParams {
    public final Algorithm algorithm;
    public final int bitLength;

    private KeyParams(Algorithm algorithm, int bitLength) {
      this.algorithm = algorithm;
      this.bitLength = bitLength;
    }
  }

  /** Algorithm parameters for RSA keys. */
  public static final class RsaKeyParams extends KeyParams {
    private RsaKeyParams(int bitLength) {
      super(Algorithm.RSA, bitLength);
    }
  }

  /** Algorithm parameters for EC keys. */
  public static final class EcKeyParams extends KeyParams {
    private final EllipticCurveValues ellipticCurveValues;

    private EcKeyParams(EllipticCurveValues ellipticCurveValues) {
      super(Algorithm.EC, ellipticCurveValues.getBitLength());
      this.ellipticCurveValues = ellipticCurveValues;
    }

    EllipticCurveValues getCurveParams() {
      return ellipticCurveValues;
    }
  }

  /** Algorithm parameters for ML-DSA keys. */
  public static final class MlDsaKeyParams extends KeyParams {
    private final MlDsaParameterValues parameterValues;

    private MlDsaKeyParams(MlDsaParameterValues parameterValues) {
      super(Algorithm.MLDSA, NO_BIT_LENGTH);
      this.parameterValues = parameterValues;
    }

    MlDsaParameterValues getParameterValues() {
      return parameterValues;
    }
  }

  /** Algorithm parameters for ML-KEM keys. */
  public static final class MlKemKeyParams extends KeyParams {
    private final MlKemParameterValues parameterValues;

    private MlKemKeyParams(MlKemParameterValues parameterValues) {
      super(Algorithm.MLKEM, NO_BIT_LENGTH);
      this.parameterValues = parameterValues;
    }

    MlKemParameterValues getParameterValues() {
      return parameterValues;
    }
  }
}

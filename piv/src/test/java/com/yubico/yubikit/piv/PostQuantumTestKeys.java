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

package com.yubico.yubikit.piv;

import com.yubico.yubikit.core.keys.MlDsaParameterValues;
import com.yubico.yubikit.core.keys.MlKemParameterValues;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.List;

/**
 * Builds ML-DSA and ML-KEM keys for tests, without relying on a security provider which supports
 * them.
 */
final class PostQuantumTestKeys {
  static final List<KeyType> ML_DSA_KEY_TYPES =
      Arrays.asList(KeyType.MLDSA44, KeyType.MLDSA65, KeyType.MLDSA87);
  static final List<KeyType> ML_KEM_KEY_TYPES =
      Arrays.asList(KeyType.MLKEM512, KeyType.MLKEM768, KeyType.MLKEM1024);

  // The algorithm identifiers are 2.16.840.1.101.3.4.<family>.<n>, with the family of the
  // signature algorithms (ML-DSA, n = 17, 18, 19) and of the key encapsulation mechanisms (ML-KEM,
  // n = 1, 2, 3).
  private static final int OID_FAMILY_SIGNATURE = 3;
  private static final int OID_FAMILY_KEM = 4;

  private PostQuantumTestKeys() {
    throw new IllegalStateException();
  }

  static byte[] algorithmOid(KeyType keyType) {
    int family;
    int n;
    switch (keyType) {
      case MLDSA44:
        family = OID_FAMILY_SIGNATURE;
        n = 17;
        break;
      case MLDSA65:
        family = OID_FAMILY_SIGNATURE;
        n = 18;
        break;
      case MLDSA87:
        family = OID_FAMILY_SIGNATURE;
        n = 19;
        break;
      case MLKEM512:
        family = OID_FAMILY_KEM;
        n = 1;
        break;
      case MLKEM768:
        family = OID_FAMILY_KEM;
        n = 2;
        break;
      case MLKEM1024:
        family = OID_FAMILY_KEM;
        n = 3;
        break;
      default:
        throw new IllegalArgumentException("Not a post-quantum key type");
    }
    return new byte[] {0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, (byte) family, (byte) n};
  }

  static int seedLength(KeyType keyType) {
    return keyType.params.algorithm == KeyType.Algorithm.MLDSA
        ? MlDsaParameterValues.SEED_LEN
        : MlKemParameterValues.SEED_LEN;
  }

  static int publicKeyLength(KeyType keyType) {
    return keyType.params.algorithm == KeyType.Algorithm.MLDSA
        ? mlDsaParameters(keyType).getPublicKeyLength()
        : mlKemParameters(keyType).getPublicKeyLength();
  }

  static MlDsaParameterValues mlDsaParameters(KeyType keyType) {
    return MlDsaParameterValues.valueOf(keyType.name().replace("MLDSA", "MLDSA_"));
  }

  static MlKemParameterValues mlKemParameters(KeyType keyType) {
    return MlKemParameterValues.valueOf(keyType.name().replace("MLKEM", "MLKEM_"));
  }

  /** The bytes of a public key of the given type, which are all the given value. */
  static byte[] publicKeyBytes(KeyType keyType, int fill) {
    byte[] bytes = new byte[publicKeyLength(keyType)];
    Arrays.fill(bytes, (byte) fill);
    return bytes;
  }

  static PublicKeyValues publicKeyValues(KeyType keyType, byte[] publicKey) {
    return keyType.params.algorithm == KeyType.Algorithm.MLDSA
        ? new PublicKeyValues.MlDsa(mlDsaParameters(keyType), publicKey)
        : new PublicKeyValues.MlKem(mlKemParameters(keyType), publicKey);
  }

  static PublicKey publicKey(KeyType keyType, byte[] publicKey) {
    return new StubPublicKey(publicKeyValues(keyType, publicKey).getEncoded());
  }

  /** A private key which holds the seed, as encoded in a PKCS#8 PrivateKeyInfo. */
  static PrivateKey privateKey(KeyType keyType, byte[] seed) {
    return new StubPrivateKey(
        new Tlv(
                0x30,
                Tlvs.encodeList(
                    Arrays.asList(
                        new Tlv(0x02, new byte[] {0}),
                        new Tlv(0x30, new Tlv(0x06, algorithmOid(keyType)).getBytes()),
                        new Tlv(0x04, new Tlv(0x04, seed).getBytes()))))
            .getBytes());
  }

  static PrivateKeyValues privateKeyValues(KeyType keyType, byte[] seed) {
    return PrivateKeyValues.fromPrivateKey(privateKey(keyType, seed));
  }

  private static class StubPublicKey implements PublicKey {
    private final byte[] encoded;

    StubPublicKey(byte[] encoded) {
      this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
      return "Stub";
    }

    @Override
    public String getFormat() {
      return "X.509";
    }

    @Override
    public byte[] getEncoded() {
      return encoded.clone();
    }
  }

  private static class StubPrivateKey implements PrivateKey {
    private final byte[] encoded;

    StubPrivateKey(byte[] encoded) {
      this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
      return "Stub";
    }

    @Override
    public String getFormat() {
      return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
      return encoded.clone();
    }
  }
}

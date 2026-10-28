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

import static com.yubico.yubikit.piv.PivSession.FEATURE_MLDSA;
import static com.yubico.yubikit.piv.PivSession.FEATURE_MLKEM;

import com.yubico.yubikit.core.keys.MlKemParameterValues;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Arrays;
import java.util.List;
import javax.crypto.KeyGenerator;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jcajce.SecretKeyWithEncapsulation;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;
import org.bouncycastle.jcajce.spec.KEMGenerateSpec;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.junit.Assert;
import org.junit.Assume;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Tests ML-DSA and ML-KEM keys, using BouncyCastle to check what the YubiKey produces and to
 * produce what it consumes.
 */
public class PivPostQuantumDeviceTests {

  private static final Logger logger = LoggerFactory.getLogger(PivPostQuantumDeviceTests.class);

  private static final List<KeyType> ML_DSA_KEY_TYPES =
      Arrays.asList(KeyType.MLDSA44, KeyType.MLDSA65, KeyType.MLDSA87);
  private static final List<KeyType> ML_KEM_KEY_TYPES =
      Arrays.asList(KeyType.MLKEM512, KeyType.MLKEM768, KeyType.MLKEM1024);

  private static final byte[] MESSAGE = "A message to be signed".getBytes(StandardCharsets.UTF_8);
  private static final byte[] CONTEXT = "A context".getBytes(StandardCharsets.UTF_8);

  public static void testMlDsaSignWithContext(PivSession piv, PivTestState state) throws Throwable {
    Assume.assumeTrue("No ML-DSA support", piv.supports(FEATURE_MLDSA));
    piv.authenticate(state.managementKey);

    for (KeyType keyType : ML_DSA_KEY_TYPES) {
      logger.debug("Generate key: {}", keyType);
      PublicKeyValues.MlDsa publicKey =
          (PublicKeyValues.MlDsa)
              piv.generateKey(Slot.SIGNATURE, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);

      piv.verifyPin(state.pin);
      byte[] signature = piv.rawSignWithContext(Slot.SIGNATURE, keyType, MESSAGE, CONTEXT);
      Assert.assertTrue(verify(publicKey, MESSAGE, CONTEXT, signature));
      // the context is part of what is signed
      Assert.assertFalse(verify(publicKey, MESSAGE, null, signature));
      Assert.assertFalse(
          verify(
              publicKey, MESSAGE, "Another context".getBytes(StandardCharsets.UTF_8), signature));

      // an empty context is the same as none
      piv.verifyPin(state.pin);
      signature = piv.rawSignWithContext(Slot.SIGNATURE, keyType, MESSAGE, new byte[0]);
      Assert.assertTrue(verify(publicKey, MESSAGE, null, signature));
    }
  }

  public static void testMlDsaSignExternalMu(PivSession piv, PivTestState state) throws Throwable {
    Assume.assumeTrue("No ML-DSA support", piv.supports(FEATURE_MLDSA));
    piv.authenticate(state.managementKey);

    for (KeyType keyType : ML_DSA_KEY_TYPES) {
      logger.debug("Generate key: {}", keyType);
      PublicKeyValues.MlDsa publicKey =
          (PublicKeyValues.MlDsa)
              piv.generateKey(Slot.SIGNATURE, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);

      byte[] mu = messageRepresentative(publicKey.getBytes(), MESSAGE, CONTEXT);
      piv.verifyPin(state.pin);
      byte[] signature = piv.rawSignExternalMu(Slot.SIGNATURE, keyType, mu);

      // the signature verifies against the message and the context that mu was computed from
      Assert.assertTrue(verify(publicKey, MESSAGE, CONTEXT, signature));
      Assert.assertFalse(verify(publicKey, MESSAGE, null, signature));
    }
  }

  public static void testMlKemDecapsulate(PivSession piv, PivTestState state) throws Throwable {
    Assume.assumeTrue("No ML-KEM support", piv.supports(FEATURE_MLKEM));
    piv.authenticate(state.managementKey);

    for (KeyType keyType : ML_KEM_KEY_TYPES) {
      logger.debug("Generate key: {}", keyType);
      PublicKeyValues.MlKem publicKey =
          (PublicKeyValues.MlKem)
              piv.generateKey(Slot.KEY_MANAGEMENT, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);

      assertDecapsulates(piv, state, keyType, publicKey.toPublicKey());
    }
  }

  public static void testMlKemImport(PivSession piv, PivTestState state) throws Throwable {
    Assume.assumeTrue("No ML-KEM support", piv.supports(FEATURE_MLKEM));
    piv.authenticate(state.managementKey);

    for (KeyType keyType : ML_KEM_KEY_TYPES) {
      logger.debug("Import key: {}", keyType);
      KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM", "BC");
      kpg.initialize(mlKemParameterSpec(keyType));
      KeyPair keyPair = kpg.generateKeyPair();

      PrivateKeyValues privateKey = PrivateKeyValues.fromPrivateKey(keyPair.getPrivate());
      Assert.assertEquals(
          keyType,
          piv.putKey(Slot.KEY_MANAGEMENT, privateKey, PinPolicy.DEFAULT, TouchPolicy.DEFAULT));
      privateKey.destroy();

      // the YubiKey derives the same key from the seed
      SlotMetadata metadata = piv.getSlotMetadata(Slot.KEY_MANAGEMENT);
      Assert.assertEquals(keyType, metadata.getKeyType());
      Assert.assertArrayEquals(
          keyPair.getPublic().getEncoded(), metadata.getPublicKeyValues().getEncoded());

      assertDecapsulates(piv, state, keyType, keyPair.getPublic());
    }
  }

  private static void assertDecapsulates(
      PivSession piv, PivTestState state, KeyType keyType, PublicKey publicKey) throws Throwable {
    KeyGenerator keyGenerator = KeyGenerator.getInstance("ML-KEM", "BC");
    // the shared secret as it is, without a key derivation function applied to it
    keyGenerator.init(
        new KEMGenerateSpec.Builder(publicKey, "AES", MlKemParameterValues.SHARED_SECRET_LEN * 8)
            .withNoKdf()
            .build());
    SecretKeyWithEncapsulation encapsulated =
        (SecretKeyWithEncapsulation) keyGenerator.generateKey();

    piv.verifyPin(state.pin);
    byte[] sharedSecret =
        piv.decapsulate(Slot.KEY_MANAGEMENT, keyType, encapsulated.getEncapsulation());
    Assert.assertArrayEquals(encapsulated.getEncoded(), sharedSecret);
  }

  private static MLKEMParameterSpec mlKemParameterSpec(KeyType keyType) {
    switch (keyType) {
      case MLKEM512:
        return MLKEMParameterSpec.ml_kem_512;
      case MLKEM768:
        return MLKEMParameterSpec.ml_kem_768;
      default:
        return MLKEMParameterSpec.ml_kem_1024;
    }
  }

  private static boolean verify(
      PublicKeyValues.MlDsa publicKey, byte[] message, byte[] context, byte[] signature)
      throws Exception {
    Signature verifier = Signature.getInstance("ML-DSA", "BC");
    verifier.initVerify(publicKey.toPublicKey());
    if (context != null) {
      verifier.setParameter(new ContextParameterSpec(context));
    }
    verifier.update(message);
    return verifier.verify(signature);
  }

  /** The message representative of FIPS 204: mu = H(H(pk, 64) || 0 || |ctx| || ctx || M, 64). */
  private static byte[] messageRepresentative(byte[] publicKey, byte[] message, byte[] context) {
    SHAKEDigest shake = new SHAKEDigest(256);
    byte[] tr = new byte[64];
    shake.update(publicKey, 0, publicKey.length);
    shake.doFinal(tr, 0, tr.length);

    shake.reset();
    shake.update(tr, 0, tr.length);
    shake.update((byte) 0);
    shake.update((byte) context.length);
    shake.update(context, 0, context.length);
    shake.update(message, 0, message.length);
    byte[] mu = new byte[64];
    shake.doFinal(mu, 0, mu.length);
    return mu;
  }
}

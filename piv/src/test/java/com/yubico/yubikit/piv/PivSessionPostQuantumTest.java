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

import static com.yubico.yubikit.piv.PivSessionTest.mockProtocol;
import static com.yubico.yubikit.piv.PivSessionTest.openSession;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.keys.MlKemParameterValues;
import com.yubico.yubikit.core.keys.PublicKeyValues;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;

public class PivSessionPostQuantumTest {

  private static final List<KeyType> POST_QUANTUM_KEY_TYPES = new ArrayList<>();

  static {
    POST_QUANTUM_KEY_TYPES.addAll(PostQuantumTestKeys.ML_DSA_KEY_TYPES);
    POST_QUANTUM_KEY_TYPES.addAll(PostQuantumTestKeys.ML_KEM_KEY_TYPES);
  }

  private static byte[] pattern(int length, int start) {
    byte[] data = new byte[length];
    for (int i = 0; i < length; i++) {
      data[i] = (byte) (start + i);
    }
    return data;
  }

  /**
   * Makes the protocol answer commands with the given instruction, and records them as they were
   * when sent, as secret data is cleared after use.
   */
  private static List<Apdu> answer(SmartCardProtocol protocol, byte ins, byte[] response)
      throws Exception {
    List<Apdu> received = new ArrayList<>();
    when(protocol.sendAndReceive(argThat(apdu -> apdu != null && apdu.getIns() == ins)))
        .thenAnswer(
            invocation -> {
              Apdu apdu = invocation.getArgument(0);
              received.add(
                  new Apdu(
                      apdu.getCla(),
                      apdu.getIns(),
                      apdu.getP1(),
                      apdu.getP2(),
                      apdu.getData().clone(),
                      apdu.getLe()));
              return response;
            });
    return received;
  }

  /** The command data of a private key operation, with the given operands after the response. */
  private static byte[] authenticateRequest(Tlv... operands) {
    List<Tlv> tlvs = new ArrayList<>();
    tlvs.add(new Tlv(PivSession.TAG_AUTH_RESPONSE, null));
    tlvs.addAll(Arrays.asList(operands));
    return new Tlv(PivSession.TAG_DYN_AUTH, Tlvs.encodeList(tlvs)).getBytes();
  }

  private static byte[] authenticateResponse(byte[] result) {
    return new Tlv(
            PivSession.TAG_DYN_AUTH, new Tlv(PivSession.TAG_AUTH_RESPONSE, result).getBytes())
        .getBytes();
  }

  private static void assertAuthenticate(
      Apdu apdu, KeyType keyType, Slot slot, byte[] expectedData) {
    assertEquals(PivSession.INS_AUTHENTICATE, apdu.getIns());
    assertEquals(keyType.value, apdu.getP1());
    assertEquals((byte) slot.value, apdu.getP2());
    assertArrayEquals(expectedData, apdu.getData());
  }

  @Test
  public void postQuantumKeysRequireSupportForThem() throws Exception {
    for (KeyType keyType : POST_QUANTUM_KEY_TYPES) {
      for (boolean generate : new boolean[] {true, false}) {
        try (PivSession session = openSession(mockProtocol(5, 7, 2))) {
          assertThrows(
              UnsupportedOperationException.class,
              () ->
                  session.checkKeySupport(
                      keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT, generate));
        }
        try (PivSession session = openSession(mockProtocol(6, 0, 0))) {
          session.checkKeySupport(keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT, generate);
        }
      }
    }
  }

  @Test
  public void postQuantumFeaturesFollowTheFirmwareVersion() throws Exception {
    try (PivSession session = openSession(mockProtocol(5, 7, 4))) {
      assertFalse(session.supports(PivSession.FEATURE_MLDSA));
      assertFalse(session.supports(PivSession.FEATURE_MLKEM));
    }
    try (PivSession session = openSession(mockProtocol(6, 0, 0))) {
      assertTrue(session.supports(PivSession.FEATURE_MLDSA));
      assertTrue(session.supports(PivSession.FEATURE_MLKEM));
    }
  }

  @Test
  public void generatesPostQuantumKeys() throws Exception {
    for (KeyType keyType : POST_QUANTUM_KEY_TYPES) {
      boolean signature = keyType.params.algorithm == KeyType.Algorithm.MLDSA;
      // the public key is returned in tag 87 for ML-DSA, and in tag 88 for ML-KEM
      int publicKeyTag = signature ? 0x87 : 0x88;
      byte[] publicKey = pattern(PostQuantumTestKeys.publicKeyLength(keyType), 3);

      SmartCardProtocol protocol = mockProtocol(6, 0, 0);
      List<Apdu> generate =
          answer(
              protocol,
              PivSession.INS_GENERATE_ASYMMETRIC,
              new Tlv(0x7F49, new Tlv(publicKeyTag, publicKey).getBytes()).getBytes());
      try (PivSession session = openSession(protocol)) {
        PublicKeyValues values =
            session.generateKey(Slot.SIGNATURE, keyType, PinPolicy.DEFAULT, TouchPolicy.DEFAULT);

        if (signature) {
          assertTrue(values instanceof PublicKeyValues.MlDsa);
          assertArrayEquals(publicKey, ((PublicKeyValues.MlDsa) values).getBytes());
        } else {
          assertTrue(values instanceof PublicKeyValues.MlKem);
          assertArrayEquals(publicKey, ((PublicKeyValues.MlKem) values).getBytes());
        }
      }

      assertEquals(1, generate.size());
      assertEquals((byte) Slot.SIGNATURE.value, generate.get(0).getP2());
      assertArrayEquals(
          new Tlv(
                  0xAC,
                  new Tlv(PivSession.TAG_GEN_ALGORITHM, new byte[] {keyType.value}).getBytes())
              .getBytes(),
          generate.get(0).getData());
    }
  }

  @Test
  public void importsPostQuantumKeysAsSeeds() throws Exception {
    for (KeyType keyType : POST_QUANTUM_KEY_TYPES) {
      boolean signature = keyType.params.algorithm == KeyType.Algorithm.MLDSA;
      byte[] seed = pattern(PostQuantumTestKeys.seedLength(keyType), 1);

      SmartCardProtocol protocol = mockProtocol(6, 0, 0);
      List<Apdu> importKey = answer(protocol, PivSession.INS_IMPORT_KEY, new byte[0]);
      try (PivSession session = openSession(protocol)) {
        KeyType imported =
            session.putKey(
                Slot.AUTHENTICATION,
                PostQuantumTestKeys.privateKeyValues(keyType, seed),
                PinPolicy.DEFAULT,
                TouchPolicy.DEFAULT);
        assertEquals(keyType, imported);
      }

      assertEquals(1, importKey.size());
      assertEquals(keyType.value, importKey.get(0).getP1());
      assertEquals((byte) Slot.AUTHENTICATION.value, importKey.get(0).getP2());
      // the seed is imported, in tag 09 for ML-DSA and in tag 0A for ML-KEM
      assertArrayEquals(
          new Tlv(signature ? 0x09 : 0x0A, seed).getBytes(), importKey.get(0).getData());
    }
  }

  @Test
  public void importOfPostQuantumKeysIsRejectedWithoutSupport() throws Exception {
    for (KeyType keyType : POST_QUANTUM_KEY_TYPES) {
      SmartCardProtocol protocol = mockProtocol(5, 7, 4);
      List<Apdu> importKey = answer(protocol, PivSession.INS_IMPORT_KEY, new byte[0]);
      try (PivSession session = openSession(protocol)) {
        assertThrows(
            UnsupportedOperationException.class,
            () ->
                session.putKey(
                    Slot.AUTHENTICATION,
                    PostQuantumTestKeys.privateKeyValues(
                        keyType, new byte[PostQuantumTestKeys.seedLength(keyType)]),
                    PinPolicy.DEFAULT,
                    TouchPolicy.DEFAULT));
      }
      assertTrue(importKey.isEmpty());
    }
  }

  @Test
  public void mlDsaSignsTheMessageAsIs() throws Exception {
    byte[] signature = pattern(100, 9);
    // lengths below, at and above the security strength of the key, none of which are padded
    for (int length : new int[] {0, 5, 16, 1_000}) {
      SmartCardProtocol protocol = mockProtocol(6, 0, 0);
      List<Apdu> authenticate =
          answer(protocol, PivSession.INS_AUTHENTICATE, authenticateResponse(signature));
      byte[] message = pattern(length, 1);
      try (PivSession session = openSession(protocol)) {
        assertArrayEquals(
            signature, session.rawSignOrDecrypt(Slot.SIGNATURE, KeyType.MLDSA44, message));
      }
      assertEquals(1, authenticate.size());
      assertAuthenticate(
          authenticate.get(0),
          KeyType.MLDSA44,
          Slot.SIGNATURE,
          authenticateRequest(new Tlv(PivSession.TAG_AUTH_CHALLENGE, message)));
    }
  }

  @Test
  public void mlDsaSignsWithContext() throws Exception {
    byte[] signature = pattern(100, 9);
    byte[] message = pattern(40, 1);
    byte[] context = pattern(255, 50);

    SmartCardProtocol protocol = mockProtocol(6, 0, 0);
    List<Apdu> authenticate =
        answer(protocol, PivSession.INS_AUTHENTICATE, authenticateResponse(signature));
    try (PivSession session = openSession(protocol)) {
      assertArrayEquals(
          signature, session.rawSignWithContext(Slot.SIGNATURE, KeyType.MLDSA87, message, context));
    }

    assertEquals(1, authenticate.size());
    // the context precedes the message
    assertAuthenticate(
        authenticate.get(0),
        KeyType.MLDSA87,
        Slot.SIGNATURE,
        authenticateRequest(
            new Tlv(PivSession.TAG_AUTH_CONTEXT, context),
            new Tlv(PivSession.TAG_AUTH_CHALLENGE, message)));
  }

  @Test
  public void emptyContextIsTheSameAsNoContext() throws Exception {
    byte[] message = pattern(40, 1);

    SmartCardProtocol protocol = mockProtocol(6, 0, 0);
    List<Apdu> authenticate =
        answer(protocol, PivSession.INS_AUTHENTICATE, authenticateResponse(new byte[1]));
    try (PivSession session = openSession(protocol)) {
      session.rawSignWithContext(Slot.SIGNATURE, KeyType.MLDSA65, message, new byte[0]);
      session.rawSignOrDecrypt(Slot.SIGNATURE, KeyType.MLDSA65, message);
    }

    assertEquals(2, authenticate.size());
    assertArrayEquals(authenticate.get(0).getData(), authenticate.get(1).getData());
  }

  @Test
  public void signingWithContextIsRestricted() throws Exception {
    SmartCardProtocol protocol = mockProtocol(6, 0, 0);
    List<Apdu> authenticate =
        answer(protocol, PivSession.INS_AUTHENTICATE, authenticateResponse(new byte[1]));
    try (PivSession session = openSession(protocol)) {
      // context longer than 255 bytes
      assertThrows(
          IllegalArgumentException.class,
          () ->
              session.rawSignWithContext(
                  Slot.SIGNATURE, KeyType.MLDSA44, new byte[10], new byte[256]));
      // not an ML-DSA key
      for (KeyType keyType : Arrays.asList(KeyType.ECCP256, KeyType.ED25519, KeyType.MLKEM768)) {
        assertThrows(
            IllegalArgumentException.class,
            () -> session.rawSignWithContext(Slot.SIGNATURE, keyType, new byte[10], new byte[1]));
      }
    }
    assertTrue(authenticate.isEmpty());
  }

  @Test
  public void mlDsaSignsExternalMu() throws Exception {
    byte[] signature = pattern(100, 9);
    byte[] mu = pattern(64, 20);

    SmartCardProtocol protocol = mockProtocol(6, 0, 0);
    List<Apdu> authenticate =
        answer(protocol, PivSession.INS_AUTHENTICATE, authenticateResponse(signature));
    try (PivSession session = openSession(protocol)) {
      assertArrayEquals(signature, session.rawSignExternalMu(Slot.SIGNATURE, KeyType.MLDSA44, mu));
    }

    assertEquals(1, authenticate.size());
    assertAuthenticate(
        authenticate.get(0),
        KeyType.MLDSA44,
        Slot.SIGNATURE,
        authenticateRequest(new Tlv(PivSession.TAG_AUTH_MU, mu)));
  }

  @Test
  public void externalMuIsRestricted() throws Exception {
    SmartCardProtocol protocol = mockProtocol(6, 0, 0);
    List<Apdu> authenticate =
        answer(protocol, PivSession.INS_AUTHENTICATE, authenticateResponse(new byte[1]));
    try (PivSession session = openSession(protocol)) {
      for (int length : new int[] {0, 32, 63, 65}) {
        assertThrows(
            IllegalArgumentException.class,
            () -> session.rawSignExternalMu(Slot.SIGNATURE, KeyType.MLDSA44, new byte[length]));
      }
      for (KeyType keyType : Arrays.asList(KeyType.ECCP384, KeyType.RSA2048, KeyType.MLKEM512)) {
        assertThrows(
            IllegalArgumentException.class,
            () -> session.rawSignExternalMu(Slot.SIGNATURE, keyType, new byte[64]));
      }
    }
    assertTrue(authenticate.isEmpty());
  }

  @Test
  public void mlKemDecapsulates() throws Exception {
    byte[] sharedSecret = pattern(MlKemParameterValues.SHARED_SECRET_LEN, 77);
    for (KeyType keyType : PostQuantumTestKeys.ML_KEM_KEY_TYPES) {
      byte[] ciphertext =
          pattern(PostQuantumTestKeys.mlKemParameters(keyType).getCiphertextLength(), 2);

      SmartCardProtocol protocol = mockProtocol(6, 0, 0);
      List<Apdu> authenticate =
          answer(protocol, PivSession.INS_AUTHENTICATE, authenticateResponse(sharedSecret));
      try (PivSession session = openSession(protocol)) {
        assertArrayEquals(
            sharedSecret, session.decapsulate(Slot.KEY_MANAGEMENT, keyType, ciphertext));
      }

      assertEquals(1, authenticate.size());
      assertAuthenticate(
          authenticate.get(0),
          keyType,
          Slot.KEY_MANAGEMENT,
          authenticateRequest(new Tlv(PivSession.TAG_AUTH_KEM, ciphertext)));
    }
  }

  @Test
  public void decapsulationIsRestricted() throws Exception {
    SmartCardProtocol protocol = mockProtocol(6, 0, 0);
    List<Apdu> authenticate =
        answer(protocol, PivSession.INS_AUTHENTICATE, authenticateResponse(new byte[32]));
    try (PivSession session = openSession(protocol)) {
      // a ciphertext of the wrong length for the parameter set
      assertThrows(
          IllegalArgumentException.class,
          () ->
              session.decapsulate(
                  Slot.KEY_MANAGEMENT,
                  KeyType.MLKEM768,
                  new byte[MlKemParameterValues.MLKEM_512.getCiphertextLength()]));
      // not an ML-KEM key
      for (KeyType keyType : Arrays.asList(KeyType.X25519, KeyType.ECCP256, KeyType.MLDSA44)) {
        assertThrows(
            IllegalArgumentException.class,
            () -> session.decapsulate(Slot.KEY_MANAGEMENT, keyType, new byte[768]));
      }
      // ML-KEM keys are not used for signing or decryption
      assertThrows(
          IllegalArgumentException.class,
          () -> session.rawSignOrDecrypt(Slot.KEY_MANAGEMENT, KeyType.MLKEM768, new byte[32]));
    }
    assertTrue(authenticate.isEmpty());
  }
}

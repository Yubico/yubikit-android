/*
 * Copyright (C) 2025-2026 Yubico.
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

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.Assert;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;

public class PivSessionTest {
  @Test
  public void opensOverSmartCard() throws Exception {
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.sendAndReceive(
            argThat(apdu -> apdu != null && apdu.getIns() == PivSession.INS_GET_VERSION)))
        .thenReturn(new byte[] {5, 7, 2});
    when(protocolMock.sendAndReceive(argThat(apdu -> apdu.getIns() == PivSession.INS_GET_METADATA)))
        .thenThrow(UnsupportedOperationException.class);
    try (PivSession session = new PivSession(protocolMock, null)) {
      Assert.assertEquals(new Version(5, 7, 2), session.getVersion());
      Assert.assertEquals(ManagementKeyType.TDES, session.getManagementKeyType());
    }

    verify(protocolMock).select(AppId.PIV);
    verify(protocolMock).close();
  }

  @Test
  public void rsa1024IsOnlySupportedByOlderDevices() throws Exception {
    for (boolean generate : new boolean[] {true, false}) {
      try (PivSession session = openSession(mockProtocol(5, 7, 2))) {
        session.checkKeySupport(KeyType.RSA1024, PinPolicy.DEFAULT, TouchPolicy.DEFAULT, generate);
      }

      for (Version version : new Version[] {new Version(6, 0, 0), new Version(6, 1, 2)}) {
        try (PivSession session = openSession(mockProtocol(version))) {
          Assert.assertThrows(
              UnsupportedOperationException.class,
              () ->
                  session.checkKeySupport(
                      KeyType.RSA1024, PinPolicy.DEFAULT, TouchPolicy.DEFAULT, generate));
          // other RSA sizes are unaffected
          session.checkKeySupport(
              KeyType.RSA2048, PinPolicy.DEFAULT, TouchPolicy.DEFAULT, generate);
        }
      }
    }
  }

  @Test
  public void tdesManagementKeyIsOnlySupportedByOlderDevices() throws Exception {
    byte[] key = new byte[ManagementKeyType.TDES.keyLength];

    SmartCardProtocol oldProtocol = mockProtocol(5, 7, 2);
    try (PivSession session = openSession(oldProtocol)) {
      session.setManagementKey(ManagementKeyType.TDES, key, false);
    }
    verify(oldProtocol).sendAndReceive(argThat(PivSessionTest::isSetManagementKey));

    SmartCardProtocol newProtocol = mockProtocol(6, 0, 0);
    try (PivSession session = openSession(newProtocol)) {
      Assert.assertThrows(
          UnsupportedOperationException.class,
          () -> session.setManagementKey(ManagementKeyType.TDES, key, false));
    }
    verify(newProtocol, never()).sendAndReceive(argThat(PivSessionTest::isSetManagementKey));
  }

  @Test
  public void aesManagementKeyIsSupportedByNewerDevices() throws Exception {
    SmartCardProtocol protocol = mockProtocol(6, 0, 0);
    try (PivSession session = openSession(protocol)) {
      session.setManagementKey(
          ManagementKeyType.AES192, new byte[ManagementKeyType.AES192.keyLength], false);
      Assert.assertEquals(ManagementKeyType.AES192, session.getManagementKeyType());
    }
    verify(protocol).sendAndReceive(argThat(PivSessionTest::isSetManagementKey));
  }

  @Test
  public void removedFeaturesFollowTheFirmwareVersion() throws Exception {
    try (PivSession session = openSession(mockProtocol(5, 7, 2))) {
      Assert.assertTrue(session.supports(PivSession.FEATURE_RSA1024));
      Assert.assertTrue(session.supports(PivSession.FEATURE_TDES_KEY));
    }
    try (PivSession session = openSession(mockProtocol(6, 0, 0))) {
      Assert.assertFalse(session.supports(PivSession.FEATURE_RSA1024));
      Assert.assertFalse(session.supports(PivSession.FEATURE_TDES_KEY));
    }
  }

  @Test
  public void readsBioMetadata() throws Exception {
    try (PivSession session = openSession(mockMetadata(BIO_SLOT, bioMetadata(1, 3, 1)))) {
      BioMetadata metadata = session.getBioMetadata();
      Assert.assertTrue(metadata.isConfigured());
      Assert.assertEquals(3, metadata.getAttemptsRemaining());
      Assert.assertTrue(metadata.hasTemporaryPin());
    }
  }

  @Test
  public void rejectsBioMetadataWithoutRetries() throws Exception {
    byte[][] responses = {
      Tlvs.encodeList(
          Arrays.asList(
              new Tlv(PivSession.TAG_METADATA_BIO_CONFIGURED, new byte[] {1}),
              new Tlv(PivSession.TAG_METADATA_TEMPORARY_PIN, new byte[] {0}))),
      Tlvs.encodeList(
          Arrays.asList(
              new Tlv(PivSession.TAG_METADATA_BIO_CONFIGURED, new byte[] {1}),
              new Tlv(PivSession.TAG_METADATA_RETRIES, new byte[0]),
              new Tlv(PivSession.TAG_METADATA_TEMPORARY_PIN, new byte[] {0}))),
      new byte[0],
    };
    for (byte[] response : responses) {
      try (PivSession session = openSession(mockMetadata(BIO_SLOT, response))) {
        IOException e = Assert.assertThrows(IOException.class, session::getBioMetadata);
        Assert.assertTrue(e.getCause() instanceof BadResponseException);
      }
    }
  }

  @Test
  public void readsMissingOrEmptyBioFlagsAsFalse() throws Exception {
    byte[][] responses = {
      new Tlv(PivSession.TAG_METADATA_RETRIES, new byte[] {3}).getBytes(),
      Tlvs.encodeList(
          Arrays.asList(
              new Tlv(PivSession.TAG_METADATA_BIO_CONFIGURED, new byte[0]),
              new Tlv(PivSession.TAG_METADATA_RETRIES, new byte[] {3}),
              new Tlv(PivSession.TAG_METADATA_TEMPORARY_PIN, new byte[0]))),
    };
    for (byte[] response : responses) {
      try (PivSession session = openSession(mockMetadata(BIO_SLOT, response))) {
        BioMetadata metadata = session.getBioMetadata();
        Assert.assertFalse(metadata.isConfigured());
        Assert.assertEquals(3, metadata.getAttemptsRemaining());
        Assert.assertFalse(metadata.hasTemporaryPin());
      }
    }
  }

  @Test
  public void rejectsMalformedPinMetadata() throws Exception {
    byte[] isDefault = {1};
    byte[][] responses = {
      metadata(PivSession.TAG_METADATA_IS_DEFAULT, isDefault),
      metadata(
          PivSession.TAG_METADATA_IS_DEFAULT,
          isDefault,
          PivSession.TAG_METADATA_RETRIES,
          new byte[] {3}),
      metadata(PivSession.TAG_METADATA_RETRIES, new byte[] {3, 3}),
      {PivSession.TAG_METADATA_RETRIES, 5, 3},
    };
    for (byte[] response : responses) {
      try (PivSession session = openSession(mockMetadata(PivSession.PIN_P2 & 0xFF, response))) {
        assertBadMetadata(session::getPinMetadata);
      }
    }
  }

  @Test
  public void rejectsMalformedManagementKeyMetadata() throws Exception {
    byte[] isDefault = {1};
    byte[][] responses = {
      metadata(PivSession.TAG_METADATA_IS_DEFAULT, isDefault),
      metadata(
          PivSession.TAG_METADATA_IS_DEFAULT,
          isDefault,
          PivSession.TAG_METADATA_POLICY,
          new byte[] {0}),
      metadata(
          PivSession.TAG_METADATA_IS_DEFAULT,
          isDefault,
          PivSession.TAG_METADATA_POLICY,
          new byte[] {0, 9}),
      metadata(
          PivSession.TAG_METADATA_ALGO, new byte[0],
          PivSession.TAG_METADATA_IS_DEFAULT, isDefault,
          PivSession.TAG_METADATA_POLICY, new byte[] {0, 1}),
    };
    for (byte[] response : responses) {
      // The session reads the management key metadata when it opens
      assertBadMetadata(() -> openSession(mockMetadata(MANAGEMENT_SLOT, response)));
    }
  }

  @Test
  public void rejectsMalformedSlotMetadata() throws Exception {
    byte[] algorithm = {KeyType.ECCP256.value};
    byte[] policy = {1, 1};
    byte[] origin = {PivSession.ORIGIN_GENERATED};
    byte[] publicKey = {0x04};
    byte[][] responses = {
      metadata(
          PivSession.TAG_METADATA_POLICY,
          policy,
          PivSession.TAG_METADATA_ORIGIN,
          origin,
          PivSession.TAG_METADATA_PUBLIC_KEY,
          publicKey),
      metadata(
          PivSession.TAG_METADATA_ALGO,
          algorithm,
          PivSession.TAG_METADATA_POLICY,
          new byte[] {1},
          PivSession.TAG_METADATA_ORIGIN,
          origin,
          PivSession.TAG_METADATA_PUBLIC_KEY,
          publicKey),
      metadata(
          PivSession.TAG_METADATA_ALGO,
          algorithm,
          PivSession.TAG_METADATA_POLICY,
          policy,
          PivSession.TAG_METADATA_PUBLIC_KEY,
          publicKey),
      metadata(
          PivSession.TAG_METADATA_ALGO,
          algorithm,
          PivSession.TAG_METADATA_POLICY,
          policy,
          PivSession.TAG_METADATA_ORIGIN,
          origin),
      metadata(
          PivSession.TAG_METADATA_ALGO,
          algorithm,
          PivSession.TAG_METADATA_POLICY,
          policy,
          PivSession.TAG_METADATA_ORIGIN,
          origin,
          PivSession.TAG_METADATA_PUBLIC_KEY,
          new byte[0]),
      metadata(
          PivSession.TAG_METADATA_ALGO,
          new byte[] {0x7E},
          PivSession.TAG_METADATA_POLICY,
          policy,
          PivSession.TAG_METADATA_ORIGIN,
          origin,
          PivSession.TAG_METADATA_PUBLIC_KEY,
          publicKey),
    };
    for (byte[] response : responses) {
      try (PivSession session = openSession(mockMetadata(Slot.AUTHENTICATION.value, response))) {
        assertBadMetadata(() -> session.getSlotMetadata(Slot.AUTHENTICATION));
      }
    }
  }

  /** TLVs from alternating tags and values. */
  private static byte[] metadata(Object... tagsAndValues) {
    List<Tlv> tlvs = new ArrayList<>();
    for (int i = 0; i < tagsAndValues.length; i += 2) {
      tlvs.add(new Tlv((Integer) tagsAndValues[i], (byte[]) tagsAndValues[i + 1]));
    }
    return Tlvs.encodeList(tlvs);
  }

  private static void assertBadMetadata(ThrowingRunnable call) {
    IOException e = Assert.assertThrows(IOException.class, call);
    Assert.assertTrue(String.valueOf(e.getCause()), e.getCause() instanceof BadResponseException);
  }

  private static final int MANAGEMENT_SLOT = 0x9B;

  private static byte[] bioMetadata(int configured, int retries, int temporaryPin) {
    return Tlvs.encodeList(
        Arrays.asList(
            new Tlv(PivSession.TAG_METADATA_BIO_CONFIGURED, new byte[] {(byte) configured}),
            new Tlv(PivSession.TAG_METADATA_RETRIES, new byte[] {(byte) retries}),
            new Tlv(PivSession.TAG_METADATA_TEMPORARY_PIN, new byte[] {(byte) temporaryPin})));
  }

  /** A 5.7.2 device answering metadata for p2 with the response, and no other metadata. */
  private static SmartCardProtocol mockMetadata(int p2, byte[] response) throws Exception {
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.sendAndReceive(
            argThat(apdu -> apdu != null && apdu.getIns() == PivSession.INS_GET_VERSION)))
        .thenReturn(new byte[] {5, 7, 2});
    when(protocolMock.sendAndReceive(
            argThat(apdu -> apdu != null && apdu.getIns() == PivSession.INS_GET_METADATA)))
        .thenAnswer(
            invocation -> {
              Apdu apdu = invocation.getArgument(0);
              if ((apdu.getP2() & 0xFF) == p2) {
                return response;
              }
              throw new UnsupportedOperationException();
            });
    return protocolMock;
  }

  private static final int BIO_SLOT = 0x96;

  private static boolean isSetManagementKey(Apdu apdu) {
    return apdu != null && apdu.getIns() == PivSession.INS_SET_MGMKEY;
  }

  static SmartCardProtocol mockProtocol(int major, int minor, int micro) throws Exception {
    return mockProtocol(new Version(major, minor, micro));
  }

  static SmartCardProtocol mockProtocol(Version version) throws Exception {
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.sendAndReceive(
            argThat(apdu -> apdu != null && apdu.getIns() == PivSession.INS_GET_VERSION)))
        .thenReturn(new byte[] {version.major, version.minor, version.micro});
    when(protocolMock.sendAndReceive(
            argThat(apdu -> apdu != null && apdu.getIns() == PivSession.INS_GET_METADATA)))
        .thenThrow(UnsupportedOperationException.class);
    return protocolMock;
  }

  static PivSession openSession(SmartCardProtocol protocol) throws Exception {
    return new PivSession(protocol, null);
  }
}

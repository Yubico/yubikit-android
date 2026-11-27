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

package com.yubico.yubikit.yubiotp;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.otp.OtpProtocol;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import java.util.Arrays;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

public class YubiOtpSessionTest {
  @Test
  public void opensOverSmartCard() throws Exception {
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    SmartCardConnection connectionMock = mock(SmartCardConnection.class);
    when(connectionMock.getTransport()).thenReturn(Transport.USB);
    when(protocolMock.getConnection()).thenReturn(connectionMock);
    when(protocolMock.select(any())).thenReturn(new byte[] {5, 7, 0, 0, 0, 0});
    try (YubiOtpSession session = new YubiOtpSession(protocolMock, null)) {
      Assert.assertEquals(new Version(5, 7, 0), session.getVersion());
    }

    verify(protocolMock).select(AppId.OTP);
    verify(protocolMock).close();
  }

  @Test
  public void opensOverOtp() throws Exception {
    OtpProtocol protocolMock = mock(OtpProtocol.class);
    when(protocolMock.getVersion()).thenReturn(new Version(5, 7, 0));
    when(protocolMock.readStatus()).thenReturn(new byte[] {5, 7, 0, 0, 0, 0});
    try (YubiOtpSession session = new YubiOtpSession(protocolMock)) {
      Assert.assertEquals(new Version(5, 7, 0), session.getVersion());
    }

    verify(protocolMock).close();
  }

  @Test
  public void calculateHmacSha1PadsOneByteChallenge() throws Exception {
    byte[] expected = new byte[64];
    expected[0] = 0x42;
    Assert.assertArrayEquals(expected, sentHmacChallenge(new byte[] {0x42}));
  }

  @Test
  public void calculateHmacSha1PadsWithOneAfterTrailingZero() throws Exception {
    byte[] expected = new byte[64];
    Arrays.fill(expected, (byte) 0x01);
    expected[0] = 0x00;
    Assert.assertArrayEquals(expected, sentHmacChallenge(new byte[] {0x00}));
  }

  @Test
  public void calculateHmacSha1SendsFullChallengeUnpadded() throws Exception {
    byte[] challenge = new byte[64];
    for (int i = 0; i < challenge.length; i++) {
      challenge[i] = (byte) (i + 1);
    }
    Assert.assertArrayEquals(challenge, sentHmacChallenge(challenge.clone()));
  }

  @Test
  public void calculateHmacSha1PadsEmptyChallengeWithZeros() throws Exception {
    Assert.assertArrayEquals(new byte[64], sentHmacChallenge(new byte[0]));
  }

  @Test
  public void calculateHmacSha1TruncatesLongChallenge() throws Exception {
    byte[] challenge = new byte[65];
    for (int i = 0; i < challenge.length; i++) {
      challenge[i] = (byte) (i + 1);
    }
    Assert.assertArrayEquals(Arrays.copyOf(challenge, 64), sentHmacChallenge(challenge));
  }

  @Test
  public void calculateHmacSha1RejectsNullChallenge() throws Exception {
    assertHmacChallengeRejected(null);
  }

  private static SmartCardProtocol hmacProtocolMock() throws Exception {
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    SmartCardConnection connectionMock = mock(SmartCardConnection.class);
    when(connectionMock.getTransport()).thenReturn(Transport.USB);
    when(protocolMock.getConnection()).thenReturn(connectionMock);
    when(protocolMock.select(any())).thenReturn(new byte[] {5, 7, 0, 0, 0, 0});
    when(protocolMock.sendAndReceive(any(Apdu.class))).thenReturn(new byte[20]);
    return protocolMock;
  }

  /** Returns the data of the APDU sent for an HMAC-SHA1 challenge to slot 1. */
  private static byte[] sentHmacChallenge(byte[] challenge) throws Exception {
    SmartCardProtocol protocolMock = hmacProtocolMock();
    try (YubiOtpSession session = new YubiOtpSession(protocolMock, null)) {
      Assert.assertEquals(20, session.calculateHmacSha1(Slot.ONE, challenge, null).length);
    }
    ArgumentCaptor<Apdu> apdu = ArgumentCaptor.forClass(Apdu.class);
    verify(protocolMock).sendAndReceive(apdu.capture());
    Assert.assertEquals(YubiOtpSession.INS_CONFIG, apdu.getValue().getIns());
    Assert.assertEquals(YubiOtpSession.CMD_CHALLENGE_HMAC_1, apdu.getValue().getP1());
    return apdu.getValue().getData();
  }

  private static void assertHmacChallengeRejected(byte[] challenge) throws Exception {
    SmartCardProtocol protocolMock = hmacProtocolMock();
    try (YubiOtpSession session = new YubiOtpSession(protocolMock, null)) {
      Assert.assertThrows(
          IllegalArgumentException.class,
          () -> session.calculateHmacSha1(Slot.ONE, challenge, null));
    }
    verify(protocolMock, never()).sendAndReceive(any(Apdu.class));
  }
}

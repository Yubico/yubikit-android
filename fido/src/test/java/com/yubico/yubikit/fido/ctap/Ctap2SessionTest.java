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

package com.yubico.yubikit.fido.ctap;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.fido.FidoProtocol;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import java.util.Collections;
import java.util.List;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

public class Ctap2SessionTest {
  private static final byte NFCCTAP_MSG = 0x10;
  private static final byte NFCCTAP_GETRESPONSE = 0x11;
  private static final byte P1_GET_RESPONSE_SUPPORTED = (byte) 0x80;
  private static final short SW_GETRESPONSE = (short) 0x9100;
  private static final byte STATUS_UPNEEDED = 0x02;
  private static final byte CTAP_OK = 0x00;

  private static Ctap2Session.InfoData infoData() {
    Ctap2Session.InfoData infoData = mock(Ctap2Session.InfoData.class);
    when(infoData.getVersions()).thenReturn(Collections.singletonList("FIDO_2_1"));
    when(infoData.getMaxMsgSize()).thenReturn(1024);
    return infoData;
  }

  @Test(timeout = 10_000)
  public void pollsWithGetResponseWhenPollingIsEnabled() throws Exception {
    SmartCardProtocol protocol = mock(SmartCardProtocol.class);
    when(protocol.sendAndReceive(any(Apdu.class)))
        .thenThrow(new ApduException(new byte[] {STATUS_UPNEEDED}, SW_GETRESPONSE))
        .thenReturn(new byte[] {CTAP_OK});

    try (Ctap2Session session =
        new Ctap2Session(new Version(5, 7, 0), protocol, null, infoData())) {
      session.reset(null);
    }

    ArgumentCaptor<Apdu> apdus = ArgumentCaptor.forClass(Apdu.class);
    verify(protocol, times(2)).sendAndReceive(apdus.capture());
    List<Apdu> sent = apdus.getAllValues();
    assertEquals(NFCCTAP_MSG, sent.get(0).getIns());
    assertEquals(P1_GET_RESPONSE_SUPPORTED, sent.get(0).getP1());
    assertEquals(NFCCTAP_GETRESPONSE, sent.get(1).getIns());
    assertEquals(0x00, sent.get(1).getP1());
  }

  @Test(timeout = 10_000)
  public void onlyTheFirstMessageCarriesTheRequestWhenPolling() throws Exception {
    SmartCardProtocol protocol = mock(SmartCardProtocol.class);
    when(protocol.sendAndReceive(any(Apdu.class)))
        .thenThrow(new ApduException(new byte[] {STATUS_UPNEEDED}, SW_GETRESPONSE))
        .thenThrow(new ApduException(new byte[] {STATUS_UPNEEDED}, SW_GETRESPONSE))
        .thenReturn(new byte[] {CTAP_OK});

    try (Ctap2Session session =
        new Ctap2Session(new Version(5, 7, 0), protocol, null, infoData())) {
      session.reset(null);
    }

    ArgumentCaptor<Apdu> apdus = ArgumentCaptor.forClass(Apdu.class);
    verify(protocol, times(3)).sendAndReceive(apdus.capture());
    List<Apdu> sent = apdus.getAllValues();
    assertEquals(NFCCTAP_MSG, sent.get(0).getIns());
    assertArrayEquals(new byte[] {Ctap2Session.CMD_RESET}, sent.get(0).getData());
    for (Apdu poll : sent.subList(1, sent.size())) {
      assertEquals(NFCCTAP_GETRESPONSE, poll.getIns());
      assertEquals(0, poll.getData().length);
    }
  }

  @Test
  public void opensOverSmartCard() throws Exception {
    SmartCardProtocol protocol = mock(SmartCardProtocol.class);
    Ctap2Session.InfoData infoData = mock(Ctap2Session.InfoData.class);
    when(infoData.getVersions()).thenReturn(Collections.singletonList("FIDO_2_0"));
    try (Ctap2Session session = new Ctap2Session(new Version(1, 2, 3), protocol, null, infoData)) {
      assertEquals(new Version(1, 2, 3), session.getVersion());
      assertEquals("FIDO_2_0", session.getCachedInfo().getVersions().get(0));
    }
    verify(protocol).select(AppId.FIDO);
    verify(protocol).close();
  }

  @Test
  public void opensOverFido() throws Exception {
    FidoProtocol protocol = mock(FidoProtocol.class);
    Ctap2Session.InfoData infoData = mock(Ctap2Session.InfoData.class);
    when(protocol.getVersion()).thenReturn(Version.fromBytes(new byte[] {1, 2, 3}));
    when(infoData.getVersions()).thenReturn(Collections.singletonList("FIDO_2_0"));
    try (Ctap2Session session = new Ctap2Session(protocol, infoData)) {
      assertEquals(new Version(1, 2, 3), session.getVersion());
      assertEquals("FIDO_2_0", session.getCachedInfo().getVersions().get(0));
    }
    verify(protocol).close();
  }
}

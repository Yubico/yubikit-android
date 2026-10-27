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

package com.yubico.yubikit.fido.ctap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.fido.Cbor;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

public class Ctap2SessionNfcResponseTest {
  private static final short SW_KEEPALIVE = (short) 0x9100;

  private final SmartCardProtocol protocol = mock(SmartCardProtocol.class);

  private Ctap2Session open() throws Exception {
    Ctap2Session.InfoData infoData = mock(Ctap2Session.InfoData.class);
    when(infoData.getVersions()).thenReturn(Collections.singletonList("FIDO_2_0"));
    when(infoData.getMaxMsgSize()).thenReturn(1024);
    return new Ctap2Session(new Version(5, 7, 0), protocol, null, infoData);
  }

  private static byte[] assertion(int nCreds) throws Exception {
    Map<Integer, Object> data = new HashMap<>();
    data.put(Ctap2Session.AssertionData.RESULT_AUTH_DATA, new byte[37]);
    data.put(Ctap2Session.AssertionData.RESULT_SIGNATURE, new byte[] {1, 2, 3});
    if (nCreds > 0) {
      data.put(Ctap2Session.AssertionData.RESULT_N_CREDS, nCreds);
    }
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    out.write(0x00);
    Cbor.encodeTo(out, data);
    return out.toByteArray();
  }

  private List<Ctap2Session.AssertionData> getAssertions(Ctap2Session session, CommandState state)
      throws Exception {
    return session.getAssertions("example.com", new byte[32], null, null, null, null, null, state);
  }

  @Test
  public void emptyResponseIsBadResponse() throws Exception {
    when(protocol.sendAndReceive(any())).thenReturn(new byte[0]);
    try (Ctap2Session session = open()) {
      assertThrows(BadResponseException.class, () -> session.reset(null));
    }
  }

  /** With polling turned off the response comes straight from the card, and is checked too. */
  @Test
  public void emptyResponseWithPollingDisabledIsBadResponse() throws Exception {
    when(protocol.sendAndReceive(any())).thenReturn(new byte[0]);
    try (Ctap2Session session = open()) {
      session.setPollingEnabled(false);
      assertThrows(BadResponseException.class, () -> session.reset(null));
    }
  }

  @Test
  public void statusOnlyResponseWithPollingDisabledIsEmptyResult() throws Exception {
    when(protocol.sendAndReceive(any())).thenReturn(new byte[] {0x00});
    try (Ctap2Session session = open()) {
      session.setPollingEnabled(false);
      session.reset(null);
    }
  }

  @Test
  public void statusOnlyResponseIsEmptyResult() throws Exception {
    when(protocol.sendAndReceive(any())).thenReturn(new byte[] {0x00});
    try (Ctap2Session session = open()) {
      session.reset(null);
    }
  }

  @Test
  public void emptyKeepaliveIsBadResponse() throws Exception {
    when(protocol.sendAndReceive(any())).thenThrow(new ApduException(new byte[0], SW_KEEPALIVE));
    try (Ctap2Session session = open()) {
      assertThrows(BadResponseException.class, () -> session.reset(null));
    }
  }

  @Test
  public void keepaliveThenResultSucceeds() throws Exception {
    when(protocol.sendAndReceive(any()))
        .thenThrow(new ApduException(new byte[] {1}, SW_KEEPALIVE))
        .thenReturn(new byte[] {0x00});
    try (Ctap2Session session = open()) {
      session.reset(null);
    }
  }

  @Test
  public void normalAssertionIsParsed() throws Exception {
    when(protocol.sendAndReceive(any())).thenReturn(assertion(0));
    try (Ctap2Session session = open()) {
      assertEquals(1, getAssertions(session, null).size());
    }
  }

  @Test
  public void nextAssertionUsesCallersState() throws Exception {
    final List<Byte> keepAlives = new ArrayList<>();
    CommandState state =
        new CommandState() {
          @Override
          public void onKeepAliveStatus(byte status) {
            keepAlives.add(status);
          }
        };
    when(protocol.sendAndReceive(any()))
        .thenReturn(assertion(2))
        .thenThrow(new ApduException(new byte[] {2}, SW_KEEPALIVE))
        .thenReturn(assertion(0));
    try (Ctap2Session session = open()) {
      state.cancel();
      assertEquals(2, getAssertions(session, state).size());
    }
    ArgumentCaptor<Apdu> apdus = ArgumentCaptor.forClass(Apdu.class);
    Mockito.verify(protocol, Mockito.times(3)).sendAndReceive(apdus.capture());
    // GET_NEXT_ASSERTION polls with NFCCTAP_GETRESPONSE and, as the caller cancelled, P1=0x11.
    assertEquals(0x11, apdus.getAllValues().get(2).getP1());
    assertEquals(Collections.singletonList((byte) 2), keepAlives);
  }
}

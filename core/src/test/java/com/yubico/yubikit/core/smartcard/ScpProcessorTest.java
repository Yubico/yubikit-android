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

package com.yubico.yubikit.core.smartcard;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.smartcard.scp.ScpState;
import java.util.ArrayList;
import java.util.List;
import org.junit.Test;

public class ScpProcessorTest {

  private static final int SECURE_MESSAGING_FLAG = 0x04;
  private static final int MAC_LENGTH = 8;

  private final List<Apdu> sent = new ArrayList<>();

  private final ApduProcessor recordingDelegate =
      apdu -> {
        sent.add(apdu);
        return new ApduResponse(new byte[] {(byte) 0x90, 0x00});
      };

  /**
   * A state which leaves data as it is and uses an all zero MAC, as the cryptography is not what is
   * tested here.
   */
  private static ScpState newState() {
    ScpState state = mock(ScpState.class);
    when(state.encrypt(any())).thenAnswer(invocation -> invocation.getArgument(0));
    when(state.mac(any())).thenReturn(new byte[MAC_LENGTH]);
    return state;
  }

  private ScpProcessor newProcessor() {
    return new ScpProcessor(recordingDelegate, new ShortApduFormatter(), newState());
  }

  @Test
  public void commandIsMarkedAsSecureMessagingAndMaced() throws Exception {
    newProcessor().sendApdu(new Apdu(0, 0x01, 0x02, 0x03, new byte[100]));

    assertEquals(1, sent.size());
    Apdu apdu = sent.get(0);
    assertEquals(SECURE_MESSAGING_FLAG, apdu.getCla() & SECURE_MESSAGING_FLAG);
    assertEquals(0x01, apdu.getIns());
    assertEquals(0x02, apdu.getP1());
    assertEquals(0x03, apdu.getP2());
    assertEquals(100 + MAC_LENGTH, apdu.getData().length);
  }

  @Test
  public void commandLargerThanASingleApduIsPassedOn() throws Exception {
    // The MAC covers the whole command. How it is split into APDUs is up to the delegate, so the
    // limit of a single extended APDU must not stop the command from being MACed.
    newProcessor().sendApdu(new Apdu(0, 0x01, 0, 0, new byte[10_000]));

    assertEquals(1, sent.size());
    assertEquals(10_000 + MAC_LENGTH, sent.get(0).getData().length);
  }
}

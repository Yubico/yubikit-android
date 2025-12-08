/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.openpgp;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class OpenPgpSessionTest {
  @Test
  public void opensOverSmartCard() throws Exception {
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.sendAndReceive(any()))
        .thenReturn(new byte[] {5, 7, 2})
        .thenReturn(mockApplicationRelatedData())
        .thenReturn(mockPinStatusData());

    try (OpenPgpSession session = new OpenPgpSession(protocolMock, null)) {
      assertEquals(new Version(5, 7, 2), session.getVersion());
      PwStatus pinStatus = session.getPinStatus();
      assertEquals(PinPolicy.ALWAYS, pinStatus.getPinPolicyUser());
      assertEquals(8, pinStatus.getMaxLenUser());
      assertEquals(6, pinStatus.getMaxLenReset());
      assertEquals(5, pinStatus.getMaxLenAdmin());
      assertEquals(2, pinStatus.getAttempts(Pw.USER));
      assertEquals(1, pinStatus.getAttempts(Pw.RESET));
      assertEquals(3, pinStatus.getAttempts(Pw.ADMIN));
    }

    verify(protocolMock).select(AppId.OPENPGP);
    verify(protocolMock).close();
  }

  private static byte[] mockApplicationRelatedData() {
    Map<Integer, byte[]> data = new HashMap<>();
    Map<Integer, byte[]> discretionary = new HashMap<>();
    discretionary.put(
        DiscretionaryDataObjects.TAG_EXTENDED_CAPABILITIES,
        ByteBuffer.allocate(10)
            .put(ExtendedCapabilityFlag.KDF.value)
            .put((byte) 0)
            .putShort((short) 0)
            .putShort((short) 0)
            .putShort((short) 0)
            .put((byte) 0)
            .put((byte) 0)
            .array());
    discretionary.put(
        Do.ALGORITHM_ATTRIBUTES_SIG,
        ByteBuffer.allocate(6)
            .put((byte) 1)
            .putShort((short) 0)
            .putShort((short) 0)
            .put((byte) 0)
            .array());
    discretionary.put(
        Do.ALGORITHM_ATTRIBUTES_DEC,
        ByteBuffer.allocate(6)
            .put((byte) 1)
            .putShort((short) 0)
            .putShort((short) 0)
            .put((byte) 0)
            .array());
    discretionary.put(
        Do.ALGORITHM_ATTRIBUTES_AUT,
        ByteBuffer.allocate(6)
            .put((byte) 1)
            .putShort((short) 0)
            .putShort((short) 0)
            .put((byte) 0)
            .array());
    discretionary.put(Do.PW_STATUS_BYTES, mockPinStatusData());
    discretionary.put(DiscretionaryDataObjects.TAG_FINGERPRINTS, new byte[0]);
    discretionary.put(DiscretionaryDataObjects.TAG_CA_FINGERPRINTS, new byte[0]);
    discretionary.put(DiscretionaryDataObjects.TAG_GENERATION_TIMES, new byte[0]);
    data.put(ApplicationRelatedData.TAG_DISCRETIONARY, Tlvs.encodeMap(discretionary));
    Tlv applicationRelatedData = new Tlv(Do.APPLICATION_RELATED_DATA, Tlvs.encodeMap(data));
    return applicationRelatedData.getBytes();
  }

  private static byte[] mockPinStatusData() {
    return ByteBuffer.allocate(7)
        .put((byte) 0)
        .put((byte) 8)
        .put((byte) 6)
        .put((byte) 5)
        .put((byte) 2)
        .put((byte) 1)
        .put((byte) 3)
        .array();
  }
}

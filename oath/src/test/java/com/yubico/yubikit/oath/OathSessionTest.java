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

package com.yubico.yubikit.oath;

import static com.yubico.yubikit.oath.OathSession.TAG_CHALLENGE;
import static com.yubico.yubikit.oath.OathSession.TAG_NAME;
import static com.yubico.yubikit.oath.OathSession.TAG_VERSION;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import org.mockito.stubbing.OngoingStubbing;

public class OathSessionTest {

  @Test
  public void opensOverSmartCard() throws Exception {
    final Version version = new Version(5, 7, 0);
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    byte[] response = selectResponse(version, new byte[] {1, 2, 3}, new byte[] {1, 2, 3});
    when(protocolMock.select(any(byte[].class))).thenReturn(response);

    try (OathSession session = new OathSession(protocolMock, null)) {
      assertEquals(new Version(5, 7, 0), session.getVersion());
    }

    verify(protocolMock).select(AppId.OATH);
    verify(protocolMock).close();
  }

  private static OathSession sessionReturning(byte[]... responses) throws Exception {
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.select(any(byte[].class)))
        .thenReturn(
            selectResponse(new Version(5, 7, 0), new byte[] {1, 2, 3}, new byte[] {1, 2, 3}));
    OngoingStubbing<byte[]> stub = when(protocolMock.sendAndReceive(any()));
    for (byte[] response : responses) {
      stub = stub.thenReturn(response);
    }
    return new OathSession(protocolMock, null);
  }

  private static byte[] tlv(int tag, byte... value) {
    return new Tlv(tag, value).getBytes();
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    for (byte[] part : parts) {
      out.write(part, 0, part.length);
    }
    return out.toByteArray();
  }

  private static final byte[] NAME =
      tlv(TAG_NAME, "Issuer:account".getBytes(StandardCharsets.UTF_8));

  @Test
  public void calculateCodesFormatsTotpAndSkipsHotpAndTouch() throws Exception {
    byte[] hotpName = tlv(TAG_NAME, "Issuer:hotp".getBytes(StandardCharsets.UTF_8));
    byte[] touchName = tlv(TAG_NAME, "Issuer:touch".getBytes(StandardCharsets.UTF_8));
    try (OathSession session =
        sessionReturning(
            concat(
                NAME,
                tlv(0x76, (byte) 6, (byte) 0x00, (byte) 0x12, (byte) 0xd6, (byte) 0x87),
                hotpName,
                tlv(0x77, (byte) 6),
                touchName,
                tlv(0x7c, (byte) 8)))) {
      Map<Credential, Code> codes = session.calculateCodes(0);
      assertEquals(3, codes.size());
      int present = 0;
      for (Map.Entry<Credential, Code> entry : codes.entrySet()) {
        if (entry.getValue() != null) {
          present++;
          assertEquals("account", entry.getKey().getAccountName());
          assertEquals("234567", entry.getValue().getValue());
        }
      }
      assertEquals(1, present);
    }
  }

  @Test
  public void calculateCodeReportsMalformedResponseAsIoException() throws Exception {
    try (OathSession session =
        sessionReturning(
            concat(NAME, tlv(0x76, (byte) 6, (byte) 0, (byte) 0, (byte) 0, (byte) 1)),
            tlv(0x76, (byte) 6))) {
      Credential credential = session.calculateCodes(0).keySet().iterator().next();
      assertThrows(IOException.class, () -> session.calculateCode(credential, 0L));
    }
  }

  @Test(expected = BadResponseException.class)
  public void calculateCodesRejectsDanglingName() throws Exception {
    try (OathSession session = sessionReturning(NAME)) {
      session.calculateCodes(0);
    }
  }

  @Test(expected = BadResponseException.class)
  public void calculateCodesRejectsEmptyResponseValue() throws Exception {
    try (OathSession session = sessionReturning(concat(NAME, tlv(0x76)))) {
      session.calculateCodes(0);
    }
  }

  @Test(expected = BadResponseException.class)
  public void calculateCodesRejectsOutOfRangeDigits() throws Exception {
    try (OathSession session =
        sessionReturning(
            concat(NAME, tlv(0x76, (byte) 0xff, (byte) 0, (byte) 0, (byte) 0, (byte) 1)))) {
      session.calculateCodes(0);
    }
  }

  @Test(expected = BadResponseException.class)
  public void calculateCodesRejectsZeroDigits() throws Exception {
    try (OathSession session =
        sessionReturning(
            concat(NAME, tlv(0x76, (byte) 0, (byte) 0, (byte) 0, (byte) 0, (byte) 1)))) {
      session.calculateCodes(0);
    }
  }

  @Test(expected = BadResponseException.class)
  public void calculateCodesRejectsUnknownResponseTag() throws Exception {
    try (OathSession session = sessionReturning(concat(NAME, tlv(0x42, (byte) 6)))) {
      session.calculateCodes(0);
    }
  }

  @Test(expected = BadResponseException.class)
  public void calculateCodesRejectsTruncatedResponseLength() throws Exception {
    try (OathSession session =
        sessionReturning(concat(NAME, tlv(0x76, (byte) 6, (byte) 0, (byte) 1)))) {
      session.calculateCodes(0);
    }
  }

  private static byte[] selectResponse(Version version, byte[] salt, byte[] challenge) {
    Map<Integer, byte[]> map = new HashMap<>();
    map.put(TAG_VERSION, new byte[] {version.major, version.minor, version.micro});
    map.put(TAG_NAME, salt);
    map.put(TAG_CHALLENGE, challenge);

    return Tlvs.encodeMap(map);
  }
}

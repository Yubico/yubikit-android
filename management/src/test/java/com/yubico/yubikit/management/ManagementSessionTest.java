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

package com.yubico.yubikit.management;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.fido.FidoProtocol;
import com.yubico.yubikit.core.otp.OtpProtocol;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

public class ManagementSessionTest {
  @Test
  public void opensOverSmartCard() throws Exception {
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    byte[] response = "5.7.0".getBytes(StandardCharsets.UTF_8);
    when(protocolMock.select(any(byte[].class))).thenReturn(response);

    try (ManagementSession session = new ManagementSession(protocolMock, null)) {
      assertEquals(new Version(5, 7, 0), session.getVersion());
    }

    verify(protocolMock).select(AppId.MANAGEMENT);
    verify(protocolMock).close();
  }

  @Test
  public void opensOverFido() throws Exception {
    FidoProtocol protocolMock = mock(FidoProtocol.class);
    when(protocolMock.getVersion()).thenReturn(new Version(5, 7, 2));

    try (ManagementSession session = new ManagementSession(protocolMock)) {
      assertEquals(new Version(5, 7, 2), session.getVersion());
    }

    verify(protocolMock).close();
  }

  @Test
  public void opensOverOtp() throws Exception {
    OtpProtocol protocolMock = mock(OtpProtocol.class);
    when(protocolMock.readStatus()).thenReturn(new byte[] {5, 7, 1});

    try (ManagementSession session = new ManagementSession(protocolMock)) {
      assertEquals(new Version(5, 7, 1), session.getVersion());
    }

    verify(protocolMock).close();
  }

  // DeviceInfo TLV tags used to build mocked config pages.
  private static final int TAG_USB_SUPPORTED = 0x01;
  private static final int TAG_SERIAL_NUMBER = 0x02;
  private static final int TAG_MORE_DATA = 0x10;

  /** Wraps TLVs as a config page: a leading length byte followed by the encoded TLVs. */
  private static byte[] page(Tlv... tlvs) {
    byte[] data = Tlvs.encodeList(Arrays.asList(tlvs));
    if (data.length > 0xff) {
      // The length byte holds 0-255; a larger payload would silently truncate modulo 256.
      throw new IllegalArgumentException("Config page exceeds 255 bytes: " + data.length);
    }
    ByteArrayOutputStream page = new ByteArrayOutputStream();
    page.write(data.length);
    page.write(data, 0, data.length);
    return page.toByteArray();
  }

  private static Tlv tlv(int tag, int... value) {
    byte[] bytes = new byte[value.length];
    for (int i = 0; i < value.length; i++) {
      bytes[i] = (byte) value[i];
    }
    return new Tlv(tag, bytes);
  }

  private static ManagementSession smartCardSession(SmartCardProtocol protocolMock)
      throws Exception {
    when(protocolMock.select(any(byte[].class)))
        .thenReturn("5.7.0".getBytes(StandardCharsets.UTF_8));
    return new ManagementSession(protocolMock, null);
  }

  /** Verifies that read-config APDUs were sent for exactly the given page indices, in order. */
  private static void assertPagesRead(SmartCardProtocol protocolMock, int... expectedPages)
      throws Exception {
    ArgumentCaptor<Apdu> captor = ArgumentCaptor.forClass(Apdu.class);
    verify(protocolMock, times(expectedPages.length)).sendAndReceive(captor.capture());
    List<Apdu> apdus = captor.getAllValues();
    for (int i = 0; i < expectedPages.length; i++) {
      assertEquals("INS of read " + i, ManagementSession.INS_READ_CONFIG, apdus.get(i).getIns());
      assertEquals("page index of read " + i, (byte) expectedPages[i], apdus.get(i).getP1());
    }
  }

  @Test
  public void readsSinglePageWhenNoMoreData() throws Exception {
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.sendAndReceive(any(Apdu.class)))
        .thenReturn(page(tlv(TAG_USB_SUPPORTED, 0x3f), tlv(TAG_SERIAL_NUMBER, 0, 0, 0, 42)));

    try (ManagementSession session = smartCardSession(protocolMock)) {
      DeviceInfo info = session.getDeviceInfo();
      assertEquals(Integer.valueOf(42), info.getSerialNumber());
    }

    // Only the first page is read when TAG_MORE_DATA is absent.
    assertPagesRead(protocolMock, 0);
  }

  @Test
  public void readsPageLongerThan127Bytes() throws Exception {
    // The page's leading length byte is unsigned (0-255); a page over 127 bytes must be accepted.
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.sendAndReceive(any(Apdu.class)))
        .thenReturn(page(tlv(TAG_SERIAL_NUMBER, 0, 0, 0, 42), tlv(0x66, new int[140])));

    try (ManagementSession session = smartCardSession(protocolMock)) {
      DeviceInfo info = session.getDeviceInfo();
      assertEquals(Integer.valueOf(42), info.getSerialNumber());
    }

    assertPagesRead(protocolMock, 0);
  }

  @Test
  public void readsTwoPagesWithLegacyMoreDataFlag() throws Exception {
    // Legacy firmware sends TAG_MORE_DATA = 1 to signal a single additional page, then omits it.
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.sendAndReceive(any(Apdu.class)))
        .thenReturn(
            page(tlv(TAG_USB_SUPPORTED, 0x3f), tlv(TAG_MORE_DATA, 1)),
            page(tlv(TAG_SERIAL_NUMBER, 0, 0, 0, 42)));

    try (ManagementSession session = smartCardSession(protocolMock)) {
      DeviceInfo info = session.getDeviceInfo();
      // Serial number lives on the second page, proving both pages were merged.
      assertEquals(Integer.valueOf(42), info.getSerialNumber());
    }

    assertPagesRead(protocolMock, 0, 1);
  }

  @Test
  public void readsAllPagesWhenMoreDataDeclaresPageCount() throws Exception {
    // Newer firmware may declare the total number of following pages once and omit it afterwards.
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.sendAndReceive(any(Apdu.class)))
        .thenReturn(
            page(tlv(TAG_USB_SUPPORTED, 0x3f), tlv(TAG_MORE_DATA, 2)),
            page(tlv(TAG_SERIAL_NUMBER, 0, 0, 0, 42)),
            page(tlv(TAG_SERIAL_NUMBER, 0, 0, 0, 7)));

    try (ManagementSession session = smartCardSession(protocolMock)) {
      DeviceInfo info = session.getDeviceInfo();
      // Later pages override earlier values for the same tag, so the third page wins.
      assertEquals(Integer.valueOf(7), info.getSerialNumber());
    }

    assertPagesRead(protocolMock, 0, 1, 2);
  }

  @Test(expected = BadResponseException.class)
  public void throwsOnEmptyConfigResponse() throws Exception {
    // An empty response must surface as a BadResponseException, not an index-out-of-bounds error.
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.sendAndReceive(any(Apdu.class))).thenReturn(new byte[0]);

    try (ManagementSession session = smartCardSession(protocolMock)) {
      session.getDeviceInfo();
    }
  }

  @Test(expected = BadResponseException.class)
  public void throwsWhenMoreDataCountExceedsPageIndexSpace() throws Exception {
    // A count reaching past the single-byte page index space must be rejected up front (after the
    // first read), not after hundreds of reads or by overflowing the page index.
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.sendAndReceive(any(Apdu.class)))
        .thenReturn(page(tlv(TAG_MORE_DATA, 0x01, 0x00))); // 256 pages

    try (ManagementSession session = smartCardSession(protocolMock)) {
      session.getDeviceInfo();
    }
  }

  @Test(expected = BadResponseException.class)
  public void throwsOnNegativeMoreDataCount() throws Exception {
    // A 4-byte 0xFFFFFFFF parses to -1 as a signed int; it must fail rather than silently stop.
    SmartCardProtocol protocolMock = mock(SmartCardProtocol.class);
    when(protocolMock.sendAndReceive(any(Apdu.class)))
        .thenReturn(page(tlv(TAG_MORE_DATA, 0xff, 0xff, 0xff, 0xff)));

    try (ManagementSession session = smartCardSession(protocolMock)) {
      session.getDeviceInfo();
    }
  }
}

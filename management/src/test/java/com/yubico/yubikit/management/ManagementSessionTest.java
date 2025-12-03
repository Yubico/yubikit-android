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

package com.yubico.yubikit.management;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.fido.FidoProtocol;
import com.yubico.yubikit.core.otp.OtpProtocol;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import java.nio.charset.StandardCharsets;
import org.junit.Test;

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
}

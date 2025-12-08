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

package com.yubico.yubikit.yubiotp;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.otp.OtpProtocol;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import org.junit.Assert;
import org.junit.Test;

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
}

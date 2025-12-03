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

package com.yubico.yubikit.piv;

import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import org.junit.Assert;
import org.junit.Test;

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
}

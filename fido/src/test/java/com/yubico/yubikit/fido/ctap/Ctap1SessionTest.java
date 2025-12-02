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

package com.yubico.yubikit.fido.ctap;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyByte;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.fido.FidoProtocol;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import org.junit.Assert;
import org.junit.Test;

public class Ctap1SessionTest {

  @Test
  public void opensOverSmartCard() throws Exception {
    SmartCardProtocol mock = mock(SmartCardProtocol.class);
    when(mock.sendAndReceive(argThat(apdu -> apdu.getIns() == Ctap1Session.INS_VERSION)))
        .thenReturn("U2F_V2".getBytes(StandardCharsets.UTF_8));
    try (Ctap1Session session = new Ctap1Session(mock, null)) {
      Assert.assertEquals(new Version(0, 0, 0), session.getVersion());
      Assert.assertEquals("U2F_V2", session.getU2fVersion());
    }

    verify(mock).select(AppId.FIDO);
    verify(mock).close();
  }

  @Test
  public void opensOverFido() throws Exception {
    FidoProtocol mock = mock(FidoProtocol.class);
    when(mock.getVersion()).thenReturn(new Version(1, 2, 3));
    when(mock.sendAndReceive(anyByte(), any(), any()))
        .thenReturn(
            ByteBuffer.allocate(8)
                .put("U2F_V3".getBytes(StandardCharsets.UTF_8))
                .put((byte) 0x90)
                .put((byte) 0x00)
                .array());
    try (Ctap1Session session = new Ctap1Session(mock)) {
      Assert.assertEquals(new Version(1, 2, 3), session.getVersion());
      Assert.assertEquals("U2F_V3", session.getU2fVersion());
    }

    verify(mock).close();
  }
}

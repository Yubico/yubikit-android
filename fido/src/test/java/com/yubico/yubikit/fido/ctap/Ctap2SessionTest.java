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

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.fido.FidoProtocol;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import java.util.Collections;
import org.junit.Test;

public class Ctap2SessionTest {
  @Test
  public void opensOverSmartCard() throws Exception {
    SmartCardProtocol protocol = mock(SmartCardProtocol.class);
    Ctap2Session.InfoData infoData = mock(Ctap2Session.InfoData.class);
    when(infoData.getVersions()).thenReturn(Collections.singletonList("FIDO_2_0"));
    try (Ctap2Session session = new Ctap2Session(new Version(1, 2, 3), protocol, null, infoData)) {
      assertEquals(new Version(1, 2, 3), session.getVersion());
      assertEquals("FIDO_2_0", session.getCachedInfo().getVersions().getFirst());
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
      assertEquals("FIDO_2_0", session.getCachedInfo().getVersions().getFirst());
    }
    verify(protocol).close();
  }
}

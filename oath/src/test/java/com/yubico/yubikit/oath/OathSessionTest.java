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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.Tlvs;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

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

  private byte[] selectResponse(Version version, byte[] salt, byte[] challenge) {
    Map<Integer, byte[]> map = new HashMap<>();
    map.put(TAG_VERSION, new byte[] {version.major, version.minor, version.micro});
    map.put(TAG_NAME, salt);
    map.put(TAG_CHALLENGE, challenge);

    return Tlvs.encodeMap(map);
  }
}

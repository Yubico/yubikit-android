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

package com.yubico.yubikit.core.smartcard.scp;

import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import java.io.IOException;
import org.junit.Test;

public class SecurityDomainSessionTest {
  @Test
  public void opensOverSmartCard() throws IOException, ApplicationNotAvailableException {
    SmartCardProtocol mock = mock(SmartCardProtocol.class);
    try (SecurityDomainSession session = new SecurityDomainSession(mock, null)) {
      assertThrows(UnsupportedOperationException.class, session::getVersion);
    }
    verify(mock).select(AppId.SECURITYDOMAIN);
    verify(mock).close();
  }
}

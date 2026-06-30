/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit.fido.client.extensions;

import static com.yubico.yubikit.fido.client.extensions.ExtensionTestHelper.creation;
import static com.yubico.yubikit.fido.client.extensions.ExtensionTestHelper.session;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.util.Collections;
import java.util.Map;
import org.junit.Test;

public class CredPropsExtensionTest {

  private final CredPropsExtension extension = new CredPropsExtension();
  private final PinUvAuthProtocol pinUvAuth = mock(PinUvAuthProtocol.class);

  @Test
  public void happyPathReportsResidentKey() {
    AuthenticatorSelectionCriteria selection =
        new AuthenticatorSelectionCriteria(null, ResidentKeyRequirement.REQUIRED, null);

    Extension.RegistrationProcessor processor =
        extension.makeCredential(
            session(), creation(Collections.singletonMap("credProps", true), selection), pinUvAuth);

    assertNotNull(processor);
    Map<String, Object> output =
        processor
            .getOutput(mock(AttestationObject.class), null)
            .getClientExtensionResult(SerializationType.CBOR);
    assertEquals(Collections.singletonMap("rk", true), output.get("credProps"));
  }

  @Test
  public void noExtensionInputReturnsNull() {
    assertNull(extension.makeCredential(session(), creation(null), pinUvAuth));
    assertNull(extension.makeCredential(session(), creation(Collections.emptyMap()), pinUvAuth));
  }
}

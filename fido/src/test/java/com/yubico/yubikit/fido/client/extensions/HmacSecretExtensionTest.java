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
import static com.yubico.yubikit.fido.client.extensions.ExtensionTestHelper.request;
import static com.yubico.yubikit.fido.client.extensions.ExtensionTestHelper.session;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import java.util.Collections;
import org.junit.Test;

/**
 * Tests for {@link HmacSecretExtension} input gating.
 *
 * <p>Only the "ignore" paths are unit-tested here: the happy path builds a shared secret with the
 * authenticator (key agreement / ECDH), which requires a real device and is covered by the {@code
 * testing} module's {@code PrfExtensionTests} / {@code HmacSecretExtensionTests}.
 */
public class HmacSecretExtensionTest {

  private static final String NAME = "hmac-secret";
  private final HmacSecretExtension extension = new HmacSecretExtension();
  private final PinUvAuthProtocol pinUvAuth = mock(PinUvAuthProtocol.class);

  @Test
  public void makeCredentialNotSupportedReturnsNull() {
    assertNull(
        extension.makeCredential(
            session(),
            creation(Collections.singletonMap("prf", Collections.emptyMap())),
            pinUvAuth));
  }

  @Test
  public void makeCredentialWithoutPrfOrHmacReturnsNull() {
    assertNull(
        extension.makeCredential(session(NAME), creation(Collections.emptyMap()), pinUvAuth));
  }

  @Test
  public void getAssertionNotSupportedReturnsNull() {
    assertNull(
        extension.getAssertion(
            session(),
            request(Collections.singletonMap("prf", Collections.emptyMap())),
            pinUvAuth));
  }
}

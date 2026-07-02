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
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;

import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import java.util.Collections;
import java.util.Map;
import org.junit.Test;

public class MinPinLengthExtensionTest {

  private static final String NAME = "minPinLength";
  private final MinPinLengthExtension extension = new MinPinLengthExtension();
  private final PinUvAuthProtocol pinUvAuth = mock(PinUvAuthProtocol.class);

  /** A session that supports minPinLength (extension advertised AND setMinPINLength option). */
  private com.yubico.yubikit.fido.ctap.Ctap2Session supportingSession() {
    return session(
        Collections.singletonList(NAME), Collections.singletonMap("setMinPINLength", true), 32);
  }

  @Test
  public void happyPathRequestsMinPinLength() {
    Extension.RegistrationProcessor processor =
        extension.makeCredential(
            supportingSession(), creation(Collections.singletonMap(NAME, true)), pinUvAuth);

    assertNotNull(processor);
    Map<String, Object> input = processor.getInput(null);
    assertEquals(Boolean.TRUE, input.get(NAME));
  }

  @Test
  public void notSupportedReturnsNull() {
    // Extension advertised but setMinPINLength option missing.
    assertNull(
        extension.makeCredential(
            session(NAME), creation(Collections.singletonMap(NAME, true)), pinUvAuth));
  }

  @Test
  public void noInputReturnsNull() {
    assertNull(extension.makeCredential(supportingSession(), creation(null), pinUvAuth));
    assertNull(
        extension.makeCredential(supportingSession(), creation(Collections.emptyMap()), pinUvAuth));
  }

  @Test
  public void nonBooleanInputThrows() {
    // minPinLength's client input is a boolean flag, so a non-boolean present value is malformed
    // caller input -> BAD_REQUEST (not silently coerced).
    assertThrows(
        IllegalArgumentException.class,
        () ->
            extension.makeCredential(
                supportingSession(), creation(Collections.singletonMap(NAME, 1)), pinUvAuth));
  }

  @Test
  public void falseInputIsIgnored() {
    // The boolean flag indicates whether the extension is requested: false means "not requested",
    // so it is ignored (no authenticator input), not surfaced.
    assertNull(
        extension.makeCredential(
            supportingSession(), creation(Collections.singletonMap(NAME, false)), pinUvAuth));
  }
}

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
import java.util.Collections;
import org.junit.Test;

/**
 * Input-mapping tests for {@link CredProtectExtension}. The hard-fail (enforce + unsupported) case
 * is covered by {@link ExtensionHardFailTest}.
 */
public class CredProtectExtensionTest {

  private static final String POLICY = "credentialProtectionPolicy";
  private static final String NAME = "credProtect";
  private final CredProtectExtension extension = new CredProtectExtension();
  private final PinUvAuthProtocol pinUvAuth = mock(PinUvAuthProtocol.class);

  private int credProtectInput(String policy) {
    Extension.RegistrationProcessor processor =
        extension.makeCredential(
            session(NAME), creation(Collections.singletonMap(POLICY, policy)), pinUvAuth);
    assertNotNull("Expected a processor for policy " + policy, processor);
    return (Integer) processor.getInput(null).get(NAME);
  }

  @Test
  public void happyPathMapsPolicyToValue() {
    assertEquals(0x01, credProtectInput("userVerificationOptional"));
    assertEquals(0x02, credProtectInput("userVerificationOptionalWithCredentialIDList"));
    assertEquals(0x03, credProtectInput("userVerificationRequired"));
  }

  @Test
  public void unknownPolicyIsIgnored() {
    assertNull(
        extension.makeCredential(
            session(NAME), creation(Collections.singletonMap(POLICY, "bogus")), pinUvAuth));
  }

  @Test
  public void noPolicyReturnsNull() {
    assertNull(extension.makeCredential(session(NAME), creation(null), pinUvAuth));
    assertNull(
        extension.makeCredential(session(NAME), creation(Collections.emptyMap()), pinUvAuth));
  }

  @Test
  public void malformedPolicyTypeIsIgnored() {
    // Non-String policy must be treated as absent, not throw ClassCastException.
    assertNull(
        extension.makeCredential(
            session(NAME), creation(Collections.singletonMap(POLICY, 123)), pinUvAuth));
  }
}

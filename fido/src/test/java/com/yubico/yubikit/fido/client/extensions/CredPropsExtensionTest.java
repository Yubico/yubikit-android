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
import static com.yubico.yubikit.fido.client.extensions.ExtensionTestHelper.rkSession;
import static com.yubico.yubikit.fido.client.extensions.ExtensionTestHelper.session;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.ResidentKeyRequirement;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.util.Collections;
import java.util.Map;
import org.jspecify.annotations.Nullable;
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
            rkSession(),
            creation(Collections.singletonMap("credProps", true), selection),
            pinUvAuth);

    assertNotNull(processor);
    Map<String, Object> output =
        processor
            .getOutput(mock(AttestationObject.class), null)
            .getClientExtensionResult(SerializationType.CBOR);
    assertEquals(Collections.singletonMap("rk", true), output.get("credProps"));
  }

  @Test
  public void preferredWithSupportReportsTrue() {
    assertEquals(Boolean.TRUE, reportedRk(rkSession(), ResidentKeyRequirement.PREFERRED));
  }

  @Test
  public void preferredWithoutSupportReportsFalse() {
    assertEquals(Boolean.FALSE, reportedRk(session(), ResidentKeyRequirement.PREFERRED));
  }

  @Test
  public void requiredWithoutSupportReportsFalse() {
    // rk reflects whether a discoverable credential was actually created: it cannot be if the
    // authenticator does not support resident keys, even when the RP required one.
    assertEquals(Boolean.FALSE, reportedRk(session(), ResidentKeyRequirement.REQUIRED));
  }

  @Test
  public void discouragedReportsFalse() {
    assertEquals(Boolean.FALSE, reportedRk(rkSession(), ResidentKeyRequirement.DISCOURAGED));
  }

  @Test
  public void noSelectionReportsFalse() {
    assertEquals(Boolean.FALSE, reportedRk(rkSession(), null));
  }

  @Test
  public void noExtensionInputReturnsNull() {
    assertNull(extension.makeCredential(session(), creation(null), pinUvAuth));
    assertNull(extension.makeCredential(session(), creation(Collections.emptyMap()), pinUvAuth));
  }

  @Test
  public void falseIsIgnored() {
    // credProps is a boolean request flag: false means "not requested" and is ignored.
    assertNull(
        extension.makeCredential(
            session(), creation(Collections.singletonMap("credProps", false)), pinUvAuth));
  }

  @Test
  public void nonBooleanThrows() {
    // A non-boolean credProps is malformed caller input -> BAD_REQUEST.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            extension.makeCredential(
                session(), creation(Collections.singletonMap("credProps", "yes")), pinUvAuth));
  }

  /**
   * Requests credProps against the given session and residentKey requirement, returning the
   * reported "rk" value (or {@code null} if the extension opts out).
   */
  @Nullable
  private Boolean reportedRk(Ctap2Session session, @Nullable String residentKey) {
    AuthenticatorSelectionCriteria selection =
        residentKey == null ? null : new AuthenticatorSelectionCriteria(null, residentKey, null);
    Extension.RegistrationProcessor processor =
        extension.makeCredential(
            session, creation(Collections.singletonMap("credProps", true), selection), pinUvAuth);
    if (processor == null) {
      return null;
    }
    Map<String, Object> output =
        processor
            .getOutput(mock(AttestationObject.class), null)
            .getClientExtensionResult(SerializationType.CBOR);
    @SuppressWarnings("unchecked")
    Map<String, Object> credProps = (Map<String, Object>) output.get("credProps");
    return (Boolean) credProps.get("rk");
  }
}

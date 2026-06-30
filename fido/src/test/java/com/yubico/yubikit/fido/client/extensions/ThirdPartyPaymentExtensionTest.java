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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.mock;

import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import java.util.Collections;
import java.util.Map;
import org.junit.Test;

public class ThirdPartyPaymentExtensionTest {

  private static final String NAME = "thirdPartyPayment";
  private final ThirdPartyPaymentExtension extension = new ThirdPartyPaymentExtension();
  private final PinUvAuthProtocol pinUvAuth = mock(PinUvAuthProtocol.class);

  private static Map<String, ?> paymentInput(boolean isPayment) {
    return Collections.singletonMap("payment", Collections.singletonMap("isPayment", isPayment));
  }

  @Test
  public void makeCredentialHappyPath() {
    Extension.RegistrationProcessor processor =
        extension.makeCredential(session(NAME), creation(paymentInput(true)), pinUvAuth);
    assertNotNull(processor);
    assertEquals(Boolean.TRUE, processor.getInput(null).get(NAME));
  }

  @Test
  public void getAssertionHappyPath() {
    Extension.AuthenticationProcessor processor =
        extension.getAssertion(session(NAME), request(paymentInput(true)), pinUvAuth);
    assertNotNull(processor);
    assertEquals(Boolean.TRUE, processor.getInput(null, null).get(NAME));
  }

  @Test
  public void notSupportedReturnsNull() {
    assertNull(extension.makeCredential(session(), creation(paymentInput(true)), pinUvAuth));
    assertNull(extension.getAssertion(session(), request(paymentInput(true)), pinUvAuth));
  }

  @Test
  public void missingPaymentDataReturnsNull() {
    assertNull(extension.makeCredential(session(NAME), creation(null), pinUvAuth));
    assertNull(
        extension.makeCredential(session(NAME), creation(Collections.emptyMap()), pinUvAuth));
    // payment present but isPayment missing
    assertNull(
        extension.makeCredential(
            session(NAME),
            creation(Collections.singletonMap("payment", Collections.emptyMap())),
            pinUvAuth));
  }
}

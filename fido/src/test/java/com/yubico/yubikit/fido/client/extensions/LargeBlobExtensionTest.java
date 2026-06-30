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
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.util.Collections;
import java.util.Map;
import org.junit.Test;

/**
 * Input-mapping tests for {@link LargeBlobExtension}. The hard-fail cases (read/write during
 * registration, and {@code support:"required"} unsupported) are covered by {@link
 * ExtensionHardFailTest}.
 */
public class LargeBlobExtensionTest {

  private static final String LARGE_BLOB = "largeBlob";
  private static final String LARGE_BLOB_KEY = "largeBlobKey";
  private final LargeBlobExtension extension = new LargeBlobExtension();
  private final PinUvAuthProtocol pinUvAuth = mock(PinUvAuthProtocol.class);

  @Test
  public void makeCredentialPreferredRequestsKey() {
    Extension.RegistrationProcessor processor =
        extension.makeCredential(
            session(),
            creation(
                Collections.singletonMap(
                    LARGE_BLOB, Collections.singletonMap("support", "preferred"))),
            pinUvAuth);

    assertNotNull(processor);
    assertEquals(Boolean.TRUE, processor.getInput(null).get(LARGE_BLOB_KEY));
  }

  @Test
  public void makeCredentialWithoutInputReturnsNull() {
    assertNull(extension.makeCredential(session(), creation(null), pinUvAuth));
    assertNull(extension.makeCredential(session(), creation(Collections.emptyMap()), pinUvAuth));
  }

  @Test
  public void getAssertionReadRequestsKey() {
    Extension.AuthenticationProcessor processor =
        extension.getAssertion(
            session(),
            request(Collections.singletonMap(LARGE_BLOB, Collections.singletonMap("read", true))),
            pinUvAuth);

    assertNotNull(processor);
    assertEquals(Boolean.TRUE, processor.getInput(null, null).get(LARGE_BLOB_KEY));
  }

  @Test
  public void getAssertionWithoutInputReturnsNull() {
    assertNull(extension.getAssertion(session(), request(null), pinUvAuth));
    assertNull(extension.getAssertion(session(), request(Collections.emptyMap()), pinUvAuth));
  }

  /**
   * A read on an authenticator that returns a largeBlobKey but does not support the large-blob
   * array makes {@code new LargeBlobs(...)} throw {@link IllegalStateException}; the extension must
   * swallow it and yield no result rather than aborting the ceremony.
   */
  @Test
  public void getAssertionReadOnUnsupportedAuthenticatorIsIgnored() {
    Ctap2Session ctap = session(); // advertises no "largeBlobs" option
    Extension.AuthenticationProcessor processor =
        extension.getAssertion(
            ctap,
            request(Collections.singletonMap(LARGE_BLOB, Collections.singletonMap("read", true))),
            pinUvAuth);
    assertNotNull(processor);

    Ctap2Session.AssertionData assertionData = mock(Ctap2Session.AssertionData.class);
    when(assertionData.getLargeBlobKey()).thenReturn(new byte[] {1, 2, 3});

    Map<String, Object> output =
        processor.getOutput(assertionData, null).getClientExtensionResult(SerializationType.CBOR);
    assertTrue(output.isEmpty());
  }

  @Test
  public void malformedLargeBlobTypeIsIgnored() {
    // A non-Map largeBlob value must be treated as absent, not throw ClassCastException.
    Map<String, ?> ext = Collections.singletonMap(LARGE_BLOB, "not-a-map");
    assertNull(extension.makeCredential(session(), creation(ext), pinUvAuth));
    assertNull(extension.getAssertion(session(), request(ext), pinUvAuth));
  }
}

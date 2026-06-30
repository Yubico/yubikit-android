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
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;

import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import java.util.Collections;
import java.util.Map;
import org.junit.Test;

public class CredBlobExtensionTest {

  private static final String NAME = "credBlob";
  private final CredBlobExtension extension = new CredBlobExtension();
  private final PinUvAuthProtocol pinUvAuth = mock(PinUvAuthProtocol.class);

  @Test
  public void happyPathSendsBlob() {
    byte[] blob = {1, 2, 3};
    Extension.RegistrationProcessor processor =
        extension.makeCredential(
            session(Collections.singletonList(NAME), Collections.emptyMap(), 32),
            creation(Collections.singletonMap(NAME, Base64.toUrlSafeString(blob))),
            pinUvAuth);

    assertNotNull(processor);
    assertArrayEquals(blob, (byte[]) processor.getInput(null).get(NAME));
  }

  @Test
  public void blobTooLongIsIgnored() {
    Extension.RegistrationProcessor processor =
        extension.makeCredential(
            session(Collections.singletonList(NAME), Collections.emptyMap(), 1),
            creation(Collections.singletonMap(NAME, Base64.toUrlSafeString(new byte[] {1, 2, 3}))),
            pinUvAuth);
    assertNull(processor);
  }

  @Test
  public void malformedCredBlobTypeThrows() {
    // credBlob is a BufferSource: a non-string is malformed structure and is surfaced
    // (BAD_REQUEST), not allowed to crash on the cast.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            extension.makeCredential(
                session(Collections.singletonList(NAME), Collections.emptyMap(), 32),
                creation(Collections.singletonMap(NAME, 123)),
                pinUvAuth));
  }

  @Test
  public void notSupportedReturnsNull() {
    assertNull(
        extension.makeCredential(
            session(),
            creation(Collections.singletonMap(NAME, Base64.toUrlSafeString(new byte[] {1}))),
            pinUvAuth));
  }

  @Test
  public void getAssertionHappyPathRequestsBlob() {
    Extension.AuthenticationProcessor processor =
        extension.getAssertion(
            session(NAME), request(Collections.singletonMap("getCredBlob", true)), pinUvAuth);

    assertNotNull(processor);
    Map<String, Object> input = processor.getInput(null, null);
    assertEquals(Boolean.TRUE, input.get(NAME));
  }

  @Test
  public void getAssertionWithoutRequestReturnsNull() {
    assertNull(extension.getAssertion(session(NAME), request(Collections.emptyMap()), pinUvAuth));
  }

  @Test
  public void getAssertionFalseGetCredBlobReturnsNull() {
    // getCredBlob is a boolean request flag: false means "not requested" and is ignored.
    assertNull(
        extension.getAssertion(
            session(NAME), request(Collections.singletonMap("getCredBlob", false)), pinUvAuth));
  }

  @Test
  public void getAssertionNonBooleanGetCredBlobThrows() {
    // A non-boolean getCredBlob is malformed caller input -> BAD_REQUEST.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            extension.getAssertion(
                session(NAME), request(Collections.singletonMap("getCredBlob", 1)), pinUvAuth));
  }
}

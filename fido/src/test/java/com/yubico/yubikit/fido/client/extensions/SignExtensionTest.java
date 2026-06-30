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
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class SignExtensionTest {

  private static final String NAME = "previewSign";
  private final SignExtension extension = new SignExtension();
  private final PinUvAuthProtocol pinUvAuth = mock(PinUvAuthProtocol.class);

  private static Map<String, ?> signInput(Map<String, ?> value) {
    return Collections.singletonMap(NAME, value);
  }

  @Test
  @SuppressWarnings("unchecked")
  public void makeCredentialHappyPath() {
    Map<String, ?> generateKey =
        Collections.singletonMap(
            "generateKey", Collections.singletonMap("algorithms", Collections.singletonList(-7)));

    Extension.RegistrationProcessor processor =
        extension.makeCredential(session(NAME), creation(signInput(generateKey)), pinUvAuth);

    assertNotNull(processor);
    Map<Integer, Object> sign = (Map<Integer, Object>) processor.getInput(null).get(NAME);
    assertEquals(Collections.singletonList(-7), sign.get(3)); // algorithms
    assertEquals(0b001, sign.get(4)); // flags (no UV)
  }

  @Test
  public void makeCredentialSignByCredentialIsIgnored() {
    Map<String, ?> input =
        signInput(Collections.singletonMap("signByCredential", Collections.emptyMap()));
    assertNull(extension.makeCredential(session(NAME), creation(input), pinUvAuth));
  }

  @Test
  public void makeCredentialWithoutGenerateKeyIsIgnored() {
    assertNull(
        extension.makeCredential(
            session(NAME), creation(signInput(Collections.emptyMap())), pinUvAuth));
  }

  @Test
  public void makeCredentialNotSupportedReturnsNull() {
    Map<String, ?> generateKey =
        Collections.singletonMap(
            "generateKey", Collections.singletonMap("algorithms", Collections.singletonList(-7)));
    assertNull(extension.makeCredential(session(), creation(signInput(generateKey)), pinUvAuth));
  }

  @Test
  @SuppressWarnings("unchecked")
  public void getAssertionHappyPath() {
    byte[] id = {9, 9};
    byte[] keyHandle = {1};
    byte[] tbs = {2};
    Map<String, Object> credEntry = new HashMap<>();
    credEntry.put("keyHandle", Base64.toUrlSafeString(keyHandle));
    credEntry.put("tbs", Base64.toUrlSafeString(tbs));
    Map<String, ?> input =
        signInput(
            Collections.singletonMap(
                "signByCredential",
                Collections.singletonMap(Base64.toUrlSafeString(id), credEntry)));

    PublicKeyCredentialDescriptor descriptor =
        new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, id);

    Extension.AuthenticationProcessor processor =
        extension.getAssertion(
            session(NAME), request(input, Collections.singletonList(descriptor)), pinUvAuth);

    assertNotNull(processor);
    Map<Integer, Object> sign =
        (Map<Integer, Object>) processor.getInput(descriptor, null).get(NAME);
    assertArrayEquals(keyHandle, (byte[]) sign.get(2));
    assertArrayEquals(tbs, (byte[]) sign.get(6));
  }

  @Test
  public void getAssertionWithGenerateKeyIsIgnored() {
    Map<String, ?> input =
        signInput(
            Collections.singletonMap(
                "generateKey",
                Collections.singletonMap("algorithms", Collections.singletonList(-7))));
    assertNull(extension.getAssertion(session(NAME), request(input), pinUvAuth));
  }

  /**
   * When the authenticator returns assertion extension outputs without the sign result, the output
   * processor must produce no result instead of dereferencing null.
   */
  @Test
  public void getAssertionMissingSignOutputProducesNoResult() {
    byte[] id = {9, 9};
    Map<String, Object> credEntry = new HashMap<>();
    credEntry.put("keyHandle", Base64.toUrlSafeString(new byte[] {1}));
    credEntry.put("tbs", Base64.toUrlSafeString(new byte[] {2}));
    Map<String, ?> input =
        signInput(
            Collections.singletonMap(
                "signByCredential",
                Collections.singletonMap(Base64.toUrlSafeString(id), credEntry)));
    PublicKeyCredentialDescriptor descriptor =
        new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, id);

    Extension.AuthenticationProcessor processor =
        extension.getAssertion(
            session(NAME), request(input, Collections.singletonList(descriptor)), pinUvAuth);
    assertNotNull(processor);

    Ctap2Session.AssertionData assertionData = mock(Ctap2Session.AssertionData.class);
    when(assertionData.getAuthenticatorData()).thenReturn(authenticatorDataWithEmptyExtensions());

    Map<String, Object> output =
        processor.getOutput(assertionData, null).getClientExtensionResult(SerializationType.CBOR);
    assertTrue(output.isEmpty());
  }

  @Test
  public void malformedSignInputIsIgnored() {
    // previewSign value is not a map.
    assertNull(
        extension.makeCredential(
            session(NAME), creation(Collections.singletonMap(NAME, "not-a-map")), pinUvAuth));
    // Nested wrong type (algorithms is not a list) must be ignored, not abort.
    Map<String, ?> badGenerateKey =
        signInput(
            Collections.singletonMap(
                "generateKey", Collections.singletonMap("algorithms", "not-a-list")));
    assertNull(extension.makeCredential(session(NAME), creation(badGenerateKey), pinUvAuth));
  }

  /** Minimal authenticator data: rpIdHash + ED flag + signCount + an empty CBOR extensions map. */
  private static byte[] authenticatorDataWithEmptyExtensions() {
    byte[] extensions = Cbor.encode(new HashMap<String, Object>());
    return ByteBuffer.allocate(32 + 1 + 4 + extensions.length)
        .put(new byte[32]) // rpIdHash
        .put((byte) 0x80) // ED flag (bit 7) set, AT clear
        .putInt(0) // signCount
        .put(extensions)
        .array();
  }
}

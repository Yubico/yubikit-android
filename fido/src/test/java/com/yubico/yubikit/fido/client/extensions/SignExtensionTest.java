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
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.nio.ByteBuffer;
import java.util.Arrays;
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

  private static Map<String, Object> credEntry() {
    Map<String, Object> entry = new HashMap<>();
    entry.put("keyHandle", Base64.toUrlSafeString(new byte[] {1}));
    entry.put("tbs", Base64.toUrlSafeString(new byte[] {2}));
    return entry;
  }

  private static Map<String, ?> signByCredential(byte[]... ids) {
    Map<String, Object> byCred = new HashMap<>();
    for (byte[] id : ids) {
      byCred.put(Base64.toUrlSafeString(id), credEntry());
    }
    return signInput(Collections.singletonMap("signByCredential", byCred));
  }

  private static PublicKeyCredentialDescriptor descriptor(byte[] id) {
    return new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, id);
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
  public void makeCredentialSignByCredentialThrows() {
    Map<String, Object> withBoth = new HashMap<>();
    withBoth.put(
        "generateKey", Collections.singletonMap("algorithms", Collections.singletonList(-7)));
    withBoth.put("signByCredential", Collections.emptyMap());
    ExtensionConfigurationException e =
        assertThrows(
            ExtensionConfigurationException.class,
            () ->
                extension.makeCredential(session(NAME), creation(signInput(withBoth)), pinUvAuth));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, e.getCode());
  }

  @Test
  public void makeCredentialWithoutGenerateKeyThrows() {
    ExtensionConfigurationException e =
        assertThrows(
            ExtensionConfigurationException.class,
            () ->
                extension.makeCredential(
                    session(NAME), creation(signInput(Collections.emptyMap())), pinUvAuth));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, e.getCode());
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
  public void getAssertionWithGenerateKeyThrows() {
    Map<String, ?> input =
        signInput(
            Collections.singletonMap(
                "generateKey",
                Collections.singletonMap("algorithms", Collections.singletonList(-7))));
    ExtensionConfigurationException e =
        assertThrows(
            ExtensionConfigurationException.class,
            () -> extension.getAssertion(session(NAME), request(input), pinUvAuth));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, e.getCode());
  }

  @Test
  public void getAssertionEmptyAllowListThrows() {
    // Spec: empty allowCredentials with signByCredential -> NotSupportedError.
    ExtensionConfigurationException e =
        assertThrows(
            ExtensionConfigurationException.class,
            () ->
                extension.getAssertion(
                    session(NAME), request(signByCredential(new byte[] {9})), pinUvAuth));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, e.getCode());
  }

  @Test
  public void getAssertionSizeMismatchThrows() {
    // Spec: signByCredential size must equal allowCredentials size -> NotSupportedError.
    byte[] id1 = {1};
    byte[] id2 = {2};
    ExtensionConfigurationException e =
        assertThrows(
            ExtensionConfigurationException.class,
            () ->
                extension.getAssertion(
                    session(NAME),
                    request(signByCredential(id1), Arrays.asList(descriptor(id1), descriptor(id2))),
                    pinUvAuth));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, e.getCode());
  }

  @Test
  public void getAssertionMissingEntryThrows() {
    // Spec: an allowed credential with no signByCredential entry -> SyntaxError (BAD_REQUEST).
    byte[] withEntry = {1};
    byte[] missing = {2};
    assertThrows(
        IllegalArgumentException.class,
        () ->
            extension.getAssertion(
                session(NAME),
                request(
                    signByCredential(withEntry), Collections.singletonList(descriptor(missing))),
                pinUvAuth));
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
  public void malformedSignInputThrows() {
    // previewSign value is not a map.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            extension.makeCredential(
                session(NAME), creation(Collections.singletonMap(NAME, "not-a-map")), pinUvAuth));
    // Nested wrong type (algorithms is not a list) must be surfaced, not silently dropped.
    Map<String, ?> badGenerateKey =
        signInput(
            Collections.singletonMap(
                "generateKey", Collections.singletonMap("algorithms", "not-a-list")));
    assertThrows(
        IllegalArgumentException.class,
        () -> extension.makeCredential(session(NAME), creation(badGenerateKey), pinUvAuth));
  }

  /**
   * When the authenticator returns malformed authenticatorData (here, the ED flag is set but no
   * extensions bytes follow, so AuthenticatorData.parseFrom throws), the output processor must
   * degrade to no result rather than letting the exception escape (and be misreported as a
   * relying-party error).
   */
  @Test
  public void getAssertionMalformedAuthOutputProducesNoResult() {
    byte[] id = {9, 9};
    Extension.AuthenticationProcessor processor =
        extension.getAssertion(
            session(NAME),
            request(signByCredential(id), Collections.singletonList(descriptor(id))),
            pinUvAuth);
    assertNotNull(processor);

    Ctap2Session.AssertionData assertionData = mock(Ctap2Session.AssertionData.class);
    when(assertionData.getAuthenticatorData()).thenReturn(malformedAuthenticatorData());

    Map<String, Object> output =
        processor.getOutput(assertionData, null).getClientExtensionResult(SerializationType.CBOR);
    assertTrue(output.isEmpty());
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

  /** Malformed authenticator data: ED flag set but no extensions bytes -> parseFrom throws. */
  private static byte[] malformedAuthenticatorData() {
    return ByteBuffer.allocate(32 + 1 + 4)
        .put(new byte[32]) // rpIdHash
        .put((byte) 0x80) // ED flag set, but no extensions data follows
        .putInt(0) // signCount
        .array();
  }
}

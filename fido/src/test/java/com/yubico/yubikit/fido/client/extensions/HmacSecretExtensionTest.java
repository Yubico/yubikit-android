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
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;

import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.Extensions;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
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
  public void makeCredentialNonBooleanHmacCreateSecretThrows() {
    // When hmac-secret is allowed, hmacCreateSecret is a boolean flag: a non-boolean value is
    // malformed caller input -> BAD_REQUEST.
    HmacSecretExtension hmacAllowed = new HmacSecretExtension(true);
    assertThrows(
        IllegalArgumentException.class,
        () ->
            hmacAllowed.makeCredential(
                session(NAME),
                creation(Collections.singletonMap("hmacCreateSecret", "yes")),
                pinUvAuth));
  }

  @Test
  public void getAssertionNotSupportedReturnsNull() {
    assertNull(
        extension.getAssertion(
            session(),
            request(Collections.singletonMap("prf", Collections.emptyMap())),
            pinUvAuth));
  }

  @Test
  public void makeCredentialMalformedPrfThrows() {
    // prf is a dictionary: a non-object value is malformed structure -> BAD_REQUEST.
    assertThrows(
        IllegalArgumentException.class,
        () ->
            extension.makeCredential(
                session(NAME),
                creation(Collections.singletonMap("prf", "not-an-object")),
                pinUvAuth));
  }

  @Test
  public void makeCredentialMalformedEvalThrows() {
    // prf.eval is a dictionary: a non-object value is malformed structure -> BAD_REQUEST.
    Map<String, Object> prf = Collections.singletonMap("eval", "not-an-object");
    assertThrows(
        IllegalArgumentException.class,
        () ->
            extension.makeCredential(
                session(NAME), creation(Collections.singletonMap("prf", prf)), pinUvAuth));
  }

  @Test
  public void makeCredentialEvalByCredentialThrows() {
    // WebAuthn prf (registration): evalByCredential is authentication-only -> NotSupportedError.
    Map<String, Object> prf =
        Collections.singletonMap(
            "evalByCredential",
            Collections.singletonMap("AA", Collections.singletonMap("first", "AA")));
    ExtensionConfigurationException e =
        assertThrows(
            ExtensionConfigurationException.class,
            () ->
                extension.makeCredential(
                    session(NAME), creation(Collections.singletonMap("prf", prf)), pinUvAuth));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, e.getCode());
  }

  @Test
  public void prepareSaltsEvalByCredentialWithoutAllowListThrows() {
    // WebAuthn prf (authentication): evalByCredential with an empty allowCredentials ->
    // NotSupportedError, carrying PRF_EVAL_BY_CREDENTIAL_REQUIRES_ALLOWLIST.
    Map<String, Object> prf =
        Collections.singletonMap(
            "evalByCredential",
            Collections.singletonMap("AA", Collections.singletonMap("first", "AA")));
    ExtensionConfigurationException e =
        assertThrows(
            ExtensionConfigurationException.class,
            () -> extension.prepareSalts(null, null, prfInputs(prf)));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, e.getCode());
  }

  @Test
  public void prepareSaltsIgnoresNullSecond() {
    // Regression: an RP sending prf.eval with "second": null (key present, null value) must not
    // crash the ceremony (previously an NPE from Base64.fromUrlSafeString(null)); the null second
    // is treated as absent, yielding first-only salts.
    Map<String, Object> eval = new HashMap<>();
    eval.put("first", "abba");
    eval.put("second", null);
    HmacSecretExtension.Salts salts = extension.prepareSalts(null, null, prfEval(eval));
    assertNotNull(salts);
    assertEquals(32, salts.salt1.length);
    assertEquals(0, salts.salt2.length);
  }

  @Test
  public void prepareSaltsProcessesFirstAndSecond() {
    Map<String, Object> eval = new HashMap<>();
    eval.put("first", "abba");
    eval.put("second", "bebe");
    HmacSecretExtension.Salts salts = extension.prepareSalts(null, null, prfEval(eval));
    assertNotNull(salts);
    assertEquals(32, salts.salt1.length);
    assertEquals(32, salts.salt2.length);
  }

  @Test
  public void prepareSaltsRejectsWrongTypedSecond() {
    // A non-string "second" is malformed input -> IllegalArgumentException (mapped to BAD_REQUEST),
    // not a crash.
    Map<String, Object> eval = new HashMap<>();
    eval.put("first", "abba");
    eval.put("second", 123);
    assertThrows(
        IllegalArgumentException.class, () -> extension.prepareSalts(null, null, prfEval(eval)));
  }

  @Test
  public void prepareSaltsRequiresFirst() {
    // A prf eval block missing "first" is malformed input -> IllegalArgumentException.
    assertThrows(
        IllegalArgumentException.class,
        () -> extension.prepareSalts(null, null, prfEval(new HashMap<>())));
  }

  /**
   * Builds parsed extension {@link HmacSecretExtension.Inputs} for {@code prf: { eval: <eval> }}.
   */
  private static HmacSecretExtension.Inputs prfEval(Map<String, Object> eval) {
    Extensions extensions =
        Extensions.fromMap(Collections.singletonMap("prf", Collections.singletonMap("eval", eval)));
    return Objects.requireNonNull(HmacSecretExtension.Inputs.fromExtensions(extensions));
  }

  /** Builds parsed extension {@link HmacSecretExtension.Inputs} for {@code prf: <prf>}. */
  private static HmacSecretExtension.Inputs prfInputs(Map<String, Object> prf) {
    Extensions extensions = Extensions.fromMap(Collections.singletonMap("prf", prf));
    return Objects.requireNonNull(HmacSecretExtension.Inputs.fromExtensions(extensions));
  }
}

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

package com.yubico.yubikit.fido.client;

import static com.yubico.yubikit.fido.ctap.ClientPin.PIN_PERMISSION_GA;
import static com.yubico.yubikit.fido.ctap.ClientPin.PIN_PERMISSION_MC;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.UserVerificationRequirement;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

/**
 * Matrix tests for {@link Ctap2Client#shouldUseUv} covering the interaction of {@code
 * userVerification}, makeCredential vs getAssertion, discoverable ({@code rk}) creation, and the
 * {@code makeCredUvNotRqd} authenticator option.
 *
 * <p>Spec basis (CTAP2.1+ §authenticatorMakeCredential, unchanged through 2.3): {@code
 * makeCredUvNotRqd} only exempts <em>non-discoverable</em> credential creation from user
 * verification; creating a discoverable ({@code rk=true}) credential on a UV-configured
 * authenticator always requires UV (otherwise the authenticator returns {@code
 * CTAP2_ERR_PUAT_REQUIRED}). {@code userVerification=discouraged} is a relying-party preference and
 * does not override that.
 */
public class Ctap2ClientShouldUseUvTest {

  /** Options for a modern PIN-configured key that supports makeCredUvNotRqd. */
  private static Map<String, Object> pinSetModern() {
    Map<String, Object> options = new HashMap<>();
    options.put("clientPin", true);
    options.put("makeCredUvNotRqd", true);
    return options;
  }

  private void assertShouldUseUv(
      Map<String, ?> options,
      String userVerification,
      int permissions,
      boolean discoverable,
      boolean expected)
      throws Throwable {
    Ctap2Session.InfoData info = mock(Ctap2Session.InfoData.class);
    doReturn(options).when(info).getOptions();
    when(info.getPinUvAuthProtocols()).thenReturn(Arrays.asList(1, 2));
    Ctap2Session ctap = mock(Ctap2Session.class);
    when(ctap.getInfo()).thenReturn(info);
    when(ctap.getCachedInfo()).thenReturn(info);
    Ctap2Client client = new Ctap2Client(ctap);

    String label =
        "uv="
            + userVerification
            + " mc="
            + ((permissions & PIN_PERMISSION_MC) != 0)
            + " discoverable="
            + discoverable;
    assertEquals(
        label, expected, client.shouldUseUv(info, userVerification, permissions, discoverable));
  }

  // --- userVerification=discouraged on a modern PIN-configured key ---

  @Test
  public void discouragedAllowListSignInDoesNotUseUv() throws Throwable {
    // getAssertion with a non-empty allowList (server-side credential) → no PIN prompt.
    assertShouldUseUv(
        pinSetModern(), UserVerificationRequirement.DISCOURAGED, PIN_PERMISSION_GA, false, false);
  }

  @Test
  public void discouragedUsernamelessSignInUsesUv() throws Throwable {
    // getAssertion with an empty allowList (discoverable/usernameless) → UV required so the
    // authenticator reveals user name/displayName for the account picker.
    assertShouldUseUv(
        pinSetModern(), UserVerificationRequirement.DISCOURAGED, PIN_PERMISSION_GA, true, true);
  }

  @Test
  public void discouragedNonDiscoverableCreateDoesNotUseUv() throws Throwable {
    // makeCredential + discouraged + rk=false + makeCredUvNotRqd → no PIN prompt.
    assertShouldUseUv(
        pinSetModern(), UserVerificationRequirement.DISCOURAGED, PIN_PERMISSION_MC, false, false);
  }

  @Test
  public void discouragedDiscoverableCreateUsesUv() throws Throwable {
    // makeCredential + discouraged + rk=true → UV required (discoverable creation always needs it).
    assertShouldUseUv(
        pinSetModern(), UserVerificationRequirement.DISCOURAGED, PIN_PERMISSION_MC, true, true);
  }

  // --- non-discouraged requirements are unaffected ---

  @Test
  public void requiredAlwaysUsesUv() throws Throwable {
    assertShouldUseUv(
        pinSetModern(), UserVerificationRequirement.REQUIRED, PIN_PERMISSION_GA, false, true);
    assertShouldUseUv(
        pinSetModern(), UserVerificationRequirement.REQUIRED, PIN_PERMISSION_MC, true, true);
  }

  @Test
  public void preferredUsesUvWhenSupported() throws Throwable {
    // clientPin present ⇒ UV supported ⇒ preferred uses UV.
    assertShouldUseUv(
        pinSetModern(), UserVerificationRequirement.PREFERRED, PIN_PERMISSION_GA, false, true);
  }

  @Test
  public void nullUserVerificationBehavesAsPreferred() throws Throwable {
    assertShouldUseUv(pinSetModern(), null, PIN_PERMISSION_GA, false, true);
  }

  // --- edge cases ---

  @Test
  public void discouragedNonDiscoverableCreateUsesUvWithoutMakeCredUvNotRqd() throws Throwable {
    // Older key that does NOT advertise makeCredUvNotRqd: even non-discoverable creation needs UV.
    Map<String, Object> pinSetLegacy = new HashMap<>();
    pinSetLegacy.put("clientPin", true);
    assertShouldUseUv(
        pinSetLegacy, UserVerificationRequirement.DISCOURAGED, PIN_PERMISSION_MC, false, true);
  }

  @Test
  public void alwaysUvForcesUvEvenForDiscouragedSignIn() throws Throwable {
    Map<String, Object> alwaysUv = pinSetModern();
    alwaysUv.put("alwaysUv", true);
    assertShouldUseUv(
        alwaysUv, UserVerificationRequirement.DISCOURAGED, PIN_PERMISSION_GA, false, true);
  }

  @Test
  public void noUvConfiguredNeverUsesUv() throws Throwable {
    // No PIN/UV configured at all: the client can't perform UV, so it never tries.
    Map<String, Object> noUv = new HashMap<>();
    assertShouldUseUv(
        noUv, UserVerificationRequirement.DISCOURAGED, PIN_PERMISSION_MC, true, false);
  }
}

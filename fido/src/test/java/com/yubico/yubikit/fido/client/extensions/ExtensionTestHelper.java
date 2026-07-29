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

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.AuthenticatorSelectionCriteria;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Shared Mockito helpers for testing {@link Extension} implementations without a real
 * authenticator.
 *
 * <p>Extensions interact with the authenticator only through {@link Ctap2Session#getCachedInfo()}
 * (to discover supported extensions/options), so mocking that is enough to drive their input/output
 * logic.
 */
final class ExtensionTestHelper {

  private ExtensionTestHelper() {}

  /** A session whose authenticator advertises the given extensions, options and credBlob length. */
  static Ctap2Session session(
      List<String> extensions, Map<String, Object> options, int maxCredBlobLength) {
    Ctap2Session.InfoData info = mock(Ctap2Session.InfoData.class);
    when(info.getExtensions()).thenReturn(extensions);
    doReturn(options).when(info).getOptions();
    when(info.getMaxCredBlobLength()).thenReturn(maxCredBlobLength);
    Ctap2Session ctap = mock(Ctap2Session.class);
    when(ctap.getCachedInfo()).thenReturn(info);
    return ctap;
  }

  /** A session advertising just the given extension names (no options). */
  static Ctap2Session session(String... extensions) {
    return session(Arrays.asList(extensions), Collections.emptyMap(), 32);
  }

  /** A session whose authenticator advertises support for resident keys (the "rk" option). */
  static Ctap2Session rkSession() {
    return session(Collections.emptyList(), Collections.singletonMap("rk", true), 32);
  }

  static PublicKeyCredentialCreationOptions creation(@Nullable Map<String, ?> extensions) {
    return creation(extensions, null);
  }

  static PublicKeyCredentialCreationOptions creation(
      @Nullable Map<String, ?> extensions, @Nullable AuthenticatorSelectionCriteria selection) {
    PublicKeyCredentialCreationOptions options = mock(PublicKeyCredentialCreationOptions.class);
    when(options.getExtensions()).thenReturn(Extensions.fromMap(extensions));
    when(options.getAuthenticatorSelection()).thenReturn(selection);
    return options;
  }

  static PublicKeyCredentialRequestOptions request(@Nullable Map<String, ?> extensions) {
    return request(extensions, Collections.emptyList());
  }

  static PublicKeyCredentialRequestOptions request(
      @Nullable Map<String, ?> extensions, List<PublicKeyCredentialDescriptor> allowCredentials) {
    PublicKeyCredentialRequestOptions options = mock(PublicKeyCredentialRequestOptions.class);
    when(options.getExtensions()).thenReturn(Extensions.fromMap(extensions));
    when(options.getAllowCredentials()).thenReturn(allowCredentials);
    return options;
  }
}

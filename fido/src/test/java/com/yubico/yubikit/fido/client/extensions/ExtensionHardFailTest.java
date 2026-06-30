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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

/**
 * Verifies that extensions which represent unsatisfiable, relying-party-requested requirements
 * raise an {@link ExtensionConfigurationException} (hard-fail) carrying the {@link
 * ClientError.Code} the client should report, rather than being silently ignored. Ignorable
 * conditions instead return {@code null}; see the extensions themselves.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#sctn-extensions">WebAuthn Extensions</a>
 */
public class ExtensionHardFailTest {

  /** A Ctap2Session whose authenticator advertises no extensions or options. */
  private static Ctap2Session sessionWithout() {
    Ctap2Session.InfoData info = mock(Ctap2Session.InfoData.class);
    when(info.getExtensions()).thenReturn(Collections.emptyList());
    // Keep the "no capabilities" authenticator valid even if an isSupported() check reaches
    // getOptions() (currently short-circuited by the empty extensions list).
    doReturn(Collections.emptyMap()).when(info).getOptions();
    Ctap2Session ctap = mock(Ctap2Session.class);
    when(ctap.getCachedInfo()).thenReturn(info);
    return ctap;
  }

  private static PublicKeyCredentialCreationOptions optionsWith(Map<String, Object> extensions) {
    PublicKeyCredentialCreationOptions options = mock(PublicKeyCredentialCreationOptions.class);
    when(options.getExtensions()).thenReturn(Extensions.fromMap(extensions));
    return options;
  }

  @Test
  public void credProtectEnforceUnsupportedThrowsConfigurationUnsupported() {
    Map<String, Object> ext = new HashMap<>();
    ext.put(CredProtectExtension.POLICY, CredProtectExtension.REQUIRED);
    ext.put(CredProtectExtension.ENFORCE, true);

    ExtensionConfigurationException error =
        assertThrows(
            ExtensionConfigurationException.class,
            () ->
                new CredProtectExtension()
                    .makeCredential(
                        sessionWithout(), optionsWith(ext), mock(PinUvAuthProtocol.class)));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, error.getCode());
  }

  @Test
  public void largeBlobRequiredUnsupportedThrowsConfigurationUnsupported() {
    Map<String, Object> largeBlob = new HashMap<>();
    largeBlob.put(LargeBlobExtension.SUPPORT, LargeBlobExtension.REQUIRED);
    Map<String, Object> ext = new HashMap<>();
    ext.put(LargeBlobExtension.LARGE_BLOB, largeBlob);

    ExtensionConfigurationException error =
        assertThrows(
            ExtensionConfigurationException.class,
            () ->
                new LargeBlobExtension()
                    .makeCredential(
                        sessionWithout(), optionsWith(ext), mock(PinUvAuthProtocol.class)));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, error.getCode());
  }

  @Test
  public void largeBlobReadInMakeCredentialThrowsConfigurationUnsupported() {
    // Spec: read/write are authentication-only; their presence during registration is a
    // NotSupportedError -> CONFIGURATION_UNSUPPORTED.
    Map<String, Object> largeBlob = new HashMap<>();
    largeBlob.put(LargeBlobExtension.ACTION_READ, true);
    Map<String, Object> ext = new HashMap<>();
    ext.put(LargeBlobExtension.LARGE_BLOB, largeBlob);

    ExtensionConfigurationException error =
        assertThrows(
            ExtensionConfigurationException.class,
            () ->
                new LargeBlobExtension()
                    .makeCredential(
                        sessionWithout(), optionsWith(ext), mock(PinUvAuthProtocol.class)));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, error.getCode());
  }
}

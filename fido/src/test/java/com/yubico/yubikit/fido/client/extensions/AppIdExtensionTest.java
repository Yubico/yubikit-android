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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.util.Collections;
import java.util.Map;
import org.junit.Test;

public class AppIdExtensionTest {
  private static final String FACET_ID = "android:apk-key-hash:test";

  private static final AppIdFacetVerifier ALLOW_ALL = (appId, facetId) -> true;
  private static final AppIdFacetVerifier DENY_ALL = (appId, facetId) -> false;

  @Test
  public void testAppIdExtensionReturnsProcessorWhenPresent() {
    AppIdExtension extension = new AppIdExtension();
    Ctap2Session ctap = mock(Ctap2Session.class);
    PinUvAuthProtocol pinUvAuthProtocol = mock(PinUvAuthProtocol.class);

    Map<String, Object> extensionsMap =
        Collections.singletonMap("appid", "https://example.com/appid.json");
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialRequestOptions options =
        new PublicKeyCredentialRequestOptions(
            new byte[] {1, 2, 3}, // challenge
            60000L, // timeout
            "example.com", // rpId
            Collections.emptyList(), // allowCredentials
            null, // userVerification
            extensions);

    Extension.AuthenticationProcessor processor =
        extension.getAssertion(ctap, options, pinUvAuthProtocol);

    assertNotNull("Processor should not be null when appid extension is present", processor);
  }

  @Test
  public void testAppIdExtensionReturnsNullWhenAbsent() {
    AppIdExtension extension = new AppIdExtension();
    Ctap2Session ctap = mock(Ctap2Session.class);
    PinUvAuthProtocol pinUvAuthProtocol = mock(PinUvAuthProtocol.class);

    PublicKeyCredentialRequestOptions options =
        new PublicKeyCredentialRequestOptions(
            new byte[] {1, 2, 3}, // challenge
            60000L, // timeout
            "example.com", // rpId
            Collections.emptyList(), // allowCredentials
            null, // userVerification
            null); // no extensions

    Extension.AuthenticationProcessor processor =
        extension.getAssertion(ctap, options, pinUvAuthProtocol);

    assertNull("Processor should be null when appid extension is absent", processor);
  }

  @Test
  public void testAppIdExtensionIgnoresInvalidInputType() {
    AppIdExtension extension = new AppIdExtension();
    Ctap2Session ctap = mock(Ctap2Session.class);
    PinUvAuthProtocol pinUvAuthProtocol = mock(PinUvAuthProtocol.class);

    // Provide invalid type (Integer instead of String)
    Map<String, Object> extensionsMap = Collections.singletonMap("appid", 12345);
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialRequestOptions options =
        new PublicKeyCredentialRequestOptions(
            new byte[] {1, 2, 3}, // challenge
            60000L, // timeout
            "example.com", // rpId
            Collections.emptyList(), // allowCredentials
            null, // userVerification
            extensions);

    Extension.AuthenticationProcessor processor =
        extension.getAssertion(ctap, options, pinUvAuthProtocol);

    assertNull("Processor should be null when appid value is not a String", processor);
  }

  @Test
  public void testAppIdExtensionOutputDefaultsFalse() throws Exception {
    AppIdExtension extension = new AppIdExtension();
    Ctap2Session ctap = mock(Ctap2Session.class);
    PinUvAuthProtocol pinUvAuthProtocol = mock(PinUvAuthProtocol.class);

    Map<String, Object> extensionsMap =
        Collections.singletonMap("appid", "https://example.com/appid.json");
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialRequestOptions options =
        new PublicKeyCredentialRequestOptions(
            new byte[] {1, 2, 3}, // challenge
            60000L, // timeout
            "example.com", // rpId
            Collections.emptyList(), // allowCredentials
            null, // userVerification
            extensions);

    Extension.AuthenticationProcessor processor =
        extension.getAssertion(ctap, options, pinUvAuthProtocol);

    assertNotNull(processor);

    // Get the output (before Ctap2Client override)
    Ctap2Session.AssertionData mockAssertionData = mock(Ctap2Session.AssertionData.class);
    Map<String, ?> output =
        processor
            .getOutput(mockAssertionData, null)
            .getClientExtensionResult(SerializationType.JSON);

    assertNotNull("Output should not be null", output);
    assertEquals("Output should default to false", false, output.get("appid"));
  }

  @Test
  public void testGetAppIdAccessor() throws Exception {
    Map<String, Object> extensionsMap =
        Collections.singletonMap("appid", "https://example.com/appid.json");
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialRequestOptions options =
        new PublicKeyCredentialRequestOptions(
            new byte[] {1, 2, 3}, // challenge
            60000L, // timeout
            "example.com", // rpId
            Collections.emptyList(), // allowCredentials
            null, // userVerification
            extensions);

    String appId = AppIdExtension.getAppId(options, FACET_ID, ALLOW_ALL);

    assertEquals("getAppId should return the appid value", "https://example.com/appid.json", appId);
  }

  @Test
  public void testGetAppIdAccessorReturnsNullWhenAbsent() throws Exception {
    PublicKeyCredentialRequestOptions options =
        new PublicKeyCredentialRequestOptions(
            new byte[] {1, 2, 3}, // challenge
            60000L, // timeout
            "example.com", // rpId
            Collections.emptyList(), // allowCredentials
            null, // userVerification
            null); // no extensions

    String appId = AppIdExtension.getAppId(options, FACET_ID, ALLOW_ALL);

    assertNull("getAppId should return null when appid extension is absent", appId);
  }

  @Test
  public void testGetAppIdAccessorFailsForInvalidType() {
    Map<String, Object> extensionsMap = Collections.singletonMap("appid", 12345);
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialRequestOptions options =
        new PublicKeyCredentialRequestOptions(
            new byte[] {1, 2, 3}, // challenge
            60000L, // timeout
            "example.com", // rpId
            Collections.emptyList(), // allowCredentials
            null, // userVerification
            extensions);

    try {
      AppIdExtension.getAppId(options, FACET_ID, ALLOW_ALL);
      fail("Expected ClientError for invalid appid type");
    } catch (ClientError e) {
      assertEquals(ClientError.Code.BAD_REQUEST, e.getErrorCode());
      assertTrue(e.getMessage().contains("must be a String"));
    }
  }

  @Test
  public void testGetAppIdAccessorSkipsWithoutFacetConfiguration() throws Exception {
    // appid is best-effort: with no FacetID/verifier configured it is skipped (returns null),
    // not treated as a hard error. (appidExclude fails closed instead — see its test.)
    Map<String, Object> extensionsMap =
        Collections.singletonMap("appid", "https://example.com/appid.json");
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialRequestOptions options =
        new PublicKeyCredentialRequestOptions(
            new byte[] {1, 2, 3}, 60000L, "example.com", Collections.emptyList(), null, extensions);

    assertNull(
        "getAppId should skip (return null) when facet configuration is missing",
        AppIdExtension.getAppId(options, null, null));
  }

  @Test
  public void testGetAppIdAccessorFailsForUnauthorizedFacet() {
    Map<String, Object> extensionsMap =
        Collections.singletonMap("appid", "https://example.com/appid.json");
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialRequestOptions options =
        new PublicKeyCredentialRequestOptions(
            new byte[] {1, 2, 3}, 60000L, "example.com", Collections.emptyList(), null, extensions);

    try {
      AppIdExtension.getAppId(options, FACET_ID, DENY_ALL);
      fail("Expected ClientError when facet is not authorized");
    } catch (ClientError e) {
      assertEquals(ClientError.Code.BAD_REQUEST, e.getErrorCode());
      assertTrue(e.getMessage().contains("not authorized"));
    }
  }
}

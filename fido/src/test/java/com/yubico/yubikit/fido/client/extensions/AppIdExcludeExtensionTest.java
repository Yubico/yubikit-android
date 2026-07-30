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
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.util.Collections;
import java.util.Map;
import org.junit.Test;

public class AppIdExcludeExtensionTest {
  private static final String FACET_ID = "android:apk-key-hash:test";
  private static final AppIdFacetVerifier ALLOW_ALL = (appId, facetId) -> true;
  private static final AppIdFacetVerifier DENY_ALL = (appId, facetId) -> false;

  @Test
  public void testAppIdExcludeExtensionReturnsProcessorWhenPresent() {
    AppIdExcludeExtension extension = new AppIdExcludeExtension();
    Ctap2Session ctap = mock(Ctap2Session.class);
    PinUvAuthProtocol pinUvAuthProtocol = mock(PinUvAuthProtocol.class);

    Map<String, Object> extensionsMap =
        Collections.singletonMap("appidExclude", "https://example.com/appid.json");
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialCreationOptions options =
        new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("Example Corp", "example.com"),
            new PublicKeyCredentialUserEntity("Test User", new byte[] {1, 2, 3}, "testuser"),
            new byte[] {1, 2, 3}, // challenge
            Collections.singletonList(
                new PublicKeyCredentialParameters("public-key", -7)), // pubKeyCredParams
            60000L, // timeout
            Collections.emptyList(), // excludeCredentials
            null, // authenticatorSelection
            null, // attestation
            extensions);

    Extension.RegistrationProcessor processor =
        extension.makeCredential(ctap, options, pinUvAuthProtocol);

    assertNotNull("Processor should not be null when appidExclude extension is present", processor);
  }

  @Test
  public void testAppIdExcludeExtensionReturnsNullWhenAbsent() {
    AppIdExcludeExtension extension = new AppIdExcludeExtension();
    Ctap2Session ctap = mock(Ctap2Session.class);
    PinUvAuthProtocol pinUvAuthProtocol = mock(PinUvAuthProtocol.class);

    PublicKeyCredentialCreationOptions options =
        new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("Example Corp", "example.com"),
            new PublicKeyCredentialUserEntity("Test User", new byte[] {1, 2, 3}, "testuser"),
            new byte[] {1, 2, 3}, // challenge
            Collections.singletonList(
                new PublicKeyCredentialParameters("public-key", -7)), // pubKeyCredParams
            60000L, // timeout
            Collections.emptyList(), // excludeCredentials
            null, // authenticatorSelection
            null, // attestation
            null); // no extensions

    Extension.RegistrationProcessor processor =
        extension.makeCredential(ctap, options, pinUvAuthProtocol);

    assertNull("Processor should be null when appidExclude extension is absent", processor);
  }

  @Test
  public void testAppIdExcludeExtensionIgnoresInvalidInputType() {
    AppIdExcludeExtension extension = new AppIdExcludeExtension();
    Ctap2Session ctap = mock(Ctap2Session.class);
    PinUvAuthProtocol pinUvAuthProtocol = mock(PinUvAuthProtocol.class);

    // Provide invalid type (Integer instead of String)
    Map<String, Object> extensionsMap = Collections.singletonMap("appidExclude", 12345);
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialCreationOptions options =
        new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("Example Corp", "example.com"),
            new PublicKeyCredentialUserEntity("Test User", new byte[] {1, 2, 3}, "testuser"),
            new byte[] {1, 2, 3}, // challenge
            Collections.singletonList(
                new PublicKeyCredentialParameters("public-key", -7)), // pubKeyCredParams
            60000L, // timeout
            Collections.emptyList(), // excludeCredentials
            null, // authenticatorSelection
            null, // attestation
            extensions);

    Extension.RegistrationProcessor processor =
        extension.makeCredential(ctap, options, pinUvAuthProtocol);

    assertNull("Processor should be null when appidExclude value is not a String", processor);
  }

  @Test
  public void testAppIdExcludeExtensionHasNoOutput() {
    AppIdExcludeExtension extension = new AppIdExcludeExtension();
    Ctap2Session ctap = mock(Ctap2Session.class);
    PinUvAuthProtocol pinUvAuthProtocol = mock(PinUvAuthProtocol.class);

    Map<String, Object> extensionsMap =
        Collections.singletonMap("appidExclude", "https://example.com/appid.json");
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialCreationOptions options =
        new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("Example Corp", "example.com"),
            new PublicKeyCredentialUserEntity("Test User", new byte[] {1, 2, 3}, "testuser"),
            new byte[] {1, 2, 3}, // challenge
            Collections.singletonList(
                new PublicKeyCredentialParameters("public-key", -7)), // pubKeyCredParams
            60000L, // timeout
            Collections.emptyList(), // excludeCredentials
            null, // authenticatorSelection
            null, // attestation
            extensions);

    Extension.RegistrationProcessor processor =
        extension.makeCredential(ctap, options, pinUvAuthProtocol);

    assertNotNull(processor);

    // Get the output (should be empty per spec)
    AttestationObject mockAttestationObject = mock(AttestationObject.class);
    Map<String, ?> output =
        processor
            .getOutput(mockAttestationObject, null)
            .getClientExtensionResult(SerializationType.JSON);

    assertTrue("Output should be empty for appidExclude extension", output.isEmpty());
  }

  @Test
  public void testGetAppIdExcludeAccessor() throws Exception {
    Map<String, Object> extensionsMap =
        Collections.singletonMap("appidExclude", "https://example.com/appid.json");
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialCreationOptions options =
        new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("Example Corp", "example.com"),
            new PublicKeyCredentialUserEntity("Test User", new byte[] {1, 2, 3}, "testuser"),
            new byte[] {1, 2, 3}, // challenge
            Collections.singletonList(
                new PublicKeyCredentialParameters("public-key", -7)), // pubKeyCredParams
            60000L, // timeout
            Collections.emptyList(), // excludeCredentials
            null, // authenticatorSelection
            null, // attestation
            extensions);

    String appIdExclude = AppIdExcludeExtension.getAppIdExclude(options, FACET_ID, ALLOW_ALL);

    assertEquals(
        "getAppIdExclude should return the appidExclude value",
        "https://example.com/appid.json",
        appIdExclude);
  }

  @Test
  public void testGetAppIdExcludeAccessorReturnsNullWhenAbsent() throws Exception {
    PublicKeyCredentialCreationOptions options =
        new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("Example Corp", "example.com"),
            new PublicKeyCredentialUserEntity("Test User", new byte[] {1, 2, 3}, "testuser"),
            new byte[] {1, 2, 3}, // challenge
            Collections.singletonList(
                new PublicKeyCredentialParameters("public-key", -7)), // pubKeyCredParams
            60000L, // timeout
            Collections.emptyList(), // excludeCredentials
            null, // authenticatorSelection
            null, // attestation
            null); // no extensions

    String appIdExclude = AppIdExcludeExtension.getAppIdExclude(options, FACET_ID, ALLOW_ALL);

    assertNull(
        "getAppIdExclude should return null when appidExclude extension is absent", appIdExclude);
  }

  @Test
  public void testGetAppIdExcludeAccessorFailsForInvalidType() {
    Map<String, Object> extensionsMap = Collections.singletonMap("appidExclude", 12345);
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialCreationOptions options =
        new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("Example Corp", "example.com"),
            new PublicKeyCredentialUserEntity("Test User", new byte[] {1, 2, 3}, "testuser"),
            new byte[] {1, 2, 3}, // challenge
            Collections.singletonList(
                new PublicKeyCredentialParameters("public-key", -7)), // pubKeyCredParams
            60000L, // timeout
            Collections.emptyList(), // excludeCredentials
            null, // authenticatorSelection
            null, // attestation
            extensions);

    try {
      AppIdExcludeExtension.getAppIdExclude(options, FACET_ID, ALLOW_ALL);
      fail("Expected ClientError for invalid appidExclude type");
    } catch (ClientError e) {
      assertEquals(ClientError.Code.BAD_REQUEST, e.getErrorCode());
      assertTrue(e.getMessage().contains("must be a String"));
    }
  }

  @Test
  public void testGetAppIdExcludeAccessorFailsWithoutFacetConfiguration() {
    Map<String, Object> extensionsMap =
        Collections.singletonMap("appidExclude", "https://example.com/appid.json");
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialCreationOptions options =
        new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("Example Corp", "example.com"),
            new PublicKeyCredentialUserEntity("Test User", new byte[] {1, 2, 3}, "testuser"),
            new byte[] {1, 2, 3},
            Collections.singletonList(new PublicKeyCredentialParameters("public-key", -7)),
            60000L,
            Collections.emptyList(),
            null,
            null,
            extensions);

    try {
      AppIdExcludeExtension.getAppIdExclude(options, null, null);
      fail("Expected ClientError when facet configuration is missing");
    } catch (ClientError e) {
      assertEquals(ClientError.Code.BAD_REQUEST, e.getErrorCode());
      assertTrue(e.getMessage().contains("requires FacetID"));
    }
  }

  @Test
  public void testGetAppIdExcludeAccessorFailsForUnauthorizedFacet() {
    Map<String, Object> extensionsMap =
        Collections.singletonMap("appidExclude", "https://example.com/appid.json");
    Extensions extensions = Extensions.fromMap(extensionsMap);

    PublicKeyCredentialCreationOptions options =
        new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("Example Corp", "example.com"),
            new PublicKeyCredentialUserEntity("Test User", new byte[] {1, 2, 3}, "testuser"),
            new byte[] {1, 2, 3},
            Collections.singletonList(new PublicKeyCredentialParameters("public-key", -7)),
            60000L,
            Collections.emptyList(),
            null,
            null,
            extensions);

    try {
      AppIdExcludeExtension.getAppIdExclude(options, FACET_ID, DENY_ALL);
      fail("Expected ClientError when facet is not authorized");
    } catch (ClientError e) {
      assertEquals(ClientError.Code.BAD_REQUEST, e.getErrorCode());
      assertTrue(e.getMessage().contains("not authorized"));
    }
  }
}

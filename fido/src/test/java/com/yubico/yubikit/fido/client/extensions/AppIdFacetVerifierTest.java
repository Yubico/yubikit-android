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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import org.junit.Test;

/**
 * Demonstrates and verifies how a host application plugs an {@link AppIdFacetVerifier} into the
 * client, exercising both an accepting and a declining verifier through the {@code appid} and
 * {@code appidExclude} extension seams.
 */
public class AppIdFacetVerifierTest {

  private static final String APP_ID = "https://example.com/appid.json";
  private static final String TRUSTED_FACET = "android:apk-key-hash:trusted";
  private static final String UNTRUSTED_FACET = "android:apk-key-hash:untrusted";

  /**
   * A reference {@link AppIdFacetVerifier} backed by an in-memory trusted-facets list.
   *
   * <p>In production the trusted-facets list is fetched from the AppID URL per the FIDO AppID and
   * Facets specification (see the FIDO module README). That network fetch is the host application's
   * responsibility; here the list is supplied directly so the authorization decision can be tested
   * without I/O.
   */
  static final class TrustedFacetsVerifier implements AppIdFacetVerifier {
    private final Map<String, Set<String>> trustedFacetsByAppId;

    TrustedFacetsVerifier(Map<String, Set<String>> trustedFacetsByAppId) {
      this.trustedFacetsByAppId = trustedFacetsByAppId;
    }

    @Override
    public boolean isAuthorizedFacet(String appId, String facetId) {
      Set<String> trusted = trustedFacetsByAppId.get(appId);
      return trusted != null && trusted.contains(facetId);
    }
  }

  private static AppIdFacetVerifier verifierTrusting(String appId, String... facets) {
    return new TrustedFacetsVerifier(
        Collections.singletonMap(appId, new HashSet<>(Arrays.asList(facets))));
  }

  private static PublicKeyCredentialRequestOptions requestWithAppId(String appId) {
    Extensions extensions = Extensions.fromMap(Collections.singletonMap("appid", appId));
    return new PublicKeyCredentialRequestOptions(
        new byte[] {1, 2, 3}, // challenge
        60000L, // timeout
        "example.com", // rpId
        Collections.emptyList(), // allowCredentials
        null, // userVerification
        extensions);
  }

  private static PublicKeyCredentialCreationOptions creationWithAppIdExclude(String appId) {
    Extensions extensions = Extensions.fromMap(Collections.singletonMap("appidExclude", appId));
    return new PublicKeyCredentialCreationOptions(
        new PublicKeyCredentialRpEntity("Example Corp", "example.com"),
        new PublicKeyCredentialUserEntity("Test User", new byte[] {1, 2, 3}, "testuser"),
        new byte[] {1, 2, 3}, // challenge
        Collections.singletonList(new PublicKeyCredentialParameters("public-key", -7)),
        60000L, // timeout
        Collections.emptyList(), // excludeCredentials
        null, // authenticatorSelection
        null, // attestation
        extensions);
  }

  // --- The verifier in isolation ---

  @Test
  public void verifierAcceptsTrustedFacet() throws Exception {
    AppIdFacetVerifier verifier = verifierTrusting(APP_ID, TRUSTED_FACET);
    assertTrue(verifier.isAuthorizedFacet(APP_ID, TRUSTED_FACET));
  }

  @Test
  public void verifierDeclinesUntrustedFacet() throws Exception {
    AppIdFacetVerifier verifier = verifierTrusting(APP_ID, TRUSTED_FACET);
    assertFalse(verifier.isAuthorizedFacet(APP_ID, UNTRUSTED_FACET));
  }

  @Test
  public void verifierDeclinesUnknownAppId() throws Exception {
    AppIdFacetVerifier verifier = verifierTrusting(APP_ID, TRUSTED_FACET);
    assertFalse(verifier.isAuthorizedFacet("https://other.example/appid.json", TRUSTED_FACET));
  }

  // --- appid extension through the SDK seam ---

  @Test
  public void appIdAcceptedWhenFacetTrusted() throws Exception {
    String appId =
        AppIdExtension.getAppId(
            requestWithAppId(APP_ID), TRUSTED_FACET, verifierTrusting(APP_ID, TRUSTED_FACET));
    assertEquals("appid should be honored when the facet is trusted", APP_ID, appId);
  }

  @Test
  public void appIdRejectedWhenFacetUntrusted() {
    try {
      AppIdExtension.getAppId(
          requestWithAppId(APP_ID), UNTRUSTED_FACET, verifierTrusting(APP_ID, TRUSTED_FACET));
      fail("Expected ClientError when the facet is not trusted");
    } catch (ClientError e) {
      assertEquals(ClientError.Code.BAD_REQUEST, e.getErrorCode());
      assertTrue(e.getMessage().contains("not authorized"));
    }
  }

  @Test
  public void appIdFailsClosedWhenVerifierThrows() {
    AppIdFacetVerifier throwing =
        (appId, facetId) -> {
          throw new IOException("trusted-facets fetch failed");
        };
    try {
      AppIdExtension.getAppId(requestWithAppId(APP_ID), TRUSTED_FACET, throwing);
      fail("Expected ClientError when the verifier throws");
    } catch (ClientError e) {
      assertEquals(ClientError.Code.BAD_REQUEST, e.getErrorCode());
      assertTrue(e.getMessage().contains("verification failed"));
    }
  }

  // --- appidExclude extension through the SDK seam ---

  @Test
  public void appIdExcludeAcceptedWhenFacetTrusted() throws Exception {
    String appId =
        AppIdExcludeExtension.getAppIdExclude(
            creationWithAppIdExclude(APP_ID),
            TRUSTED_FACET,
            verifierTrusting(APP_ID, TRUSTED_FACET));
    assertEquals("appidExclude should be honored when the facet is trusted", APP_ID, appId);
  }

  @Test
  public void appIdExcludeRejectedWhenFacetUntrusted() {
    try {
      AppIdExcludeExtension.getAppIdExclude(
          creationWithAppIdExclude(APP_ID),
          UNTRUSTED_FACET,
          verifierTrusting(APP_ID, TRUSTED_FACET));
      fail("Expected ClientError when the facet is not trusted");
    } catch (ClientError e) {
      assertEquals(ClientError.Code.BAD_REQUEST, e.getErrorCode());
      assertTrue(e.getMessage().contains("not authorized"));
    }
  }
}

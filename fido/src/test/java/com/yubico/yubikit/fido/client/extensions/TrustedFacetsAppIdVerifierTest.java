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

import com.yubico.yubikit.fido.client.extensions.TrustedFacetsAppIdVerifier.AppIdDocumentFetcher;
import java.io.IOException;
import java.util.concurrent.atomic.AtomicInteger;
import org.jspecify.annotations.Nullable;
import org.junit.Test;

public class TrustedFacetsAppIdVerifierTest {

  private static final String APP_ID = "https://example.com/appid.json";
  private static final String TRUSTED_FACET = "android:apk-key-hash:trusted";
  private static final String UNTRUSTED_FACET = "android:apk-key-hash:untrusted";

  private static final String DOCUMENT =
      "{"
          + "\"trustedFacets\":[{"
          + "\"version\":{\"major\":1,\"minor\":0},"
          + "\"ids\":[\"https://login.example.com\",\"android:apk-key-hash:trusted\"]"
          + "}]}";

  /** Fetcher returning a fixed body and counting how many times it is invoked. */
  private static final class CountingFetcher implements AppIdDocumentFetcher {
    final AtomicInteger calls = new AtomicInteger();
    @Nullable final String body;

    CountingFetcher(@Nullable String body) {
      this.body = body;
    }

    @Nullable
    @Override
    public String fetch(String appIdUrl) {
      calls.incrementAndGet();
      return body;
    }
  }

  @Test
  public void acceptsTrustedFacet() throws Exception {
    TrustedFacetsAppIdVerifier verifier =
        new TrustedFacetsAppIdVerifier(new CountingFetcher(DOCUMENT));
    assertTrue(verifier.isAuthorizedFacet(APP_ID, TRUSTED_FACET));
  }

  @Test
  public void declinesUntrustedFacet() throws Exception {
    TrustedFacetsAppIdVerifier verifier =
        new TrustedFacetsAppIdVerifier(new CountingFetcher(DOCUMENT));
    assertFalse(verifier.isAuthorizedFacet(APP_ID, UNTRUSTED_FACET));
  }

  @Test
  public void declinesWhenDocumentMissing() throws Exception {
    // A 404 surfaces as a null body: no trusted facets, so nothing is authorized.
    TrustedFacetsAppIdVerifier verifier = new TrustedFacetsAppIdVerifier(new CountingFetcher(null));
    assertFalse(verifier.isAuthorizedFacet(APP_ID, TRUSTED_FACET));
  }

  @Test
  public void cachesPerAppId() throws Exception {
    CountingFetcher fetcher = new CountingFetcher(DOCUMENT);
    TrustedFacetsAppIdVerifier verifier = new TrustedFacetsAppIdVerifier(fetcher);

    verifier.isAuthorizedFacet(APP_ID, TRUSTED_FACET);
    verifier.isAuthorizedFacet(APP_ID, UNTRUSTED_FACET);
    verifier.isAuthorizedFacet(APP_ID, TRUSTED_FACET);

    assertEquals("AppID document should be fetched only once", 1, fetcher.calls.get());
  }

  @Test
  public void transportErrorIsPropagatedAndNotCached() throws Exception {
    AtomicInteger calls = new AtomicInteger();
    AppIdDocumentFetcher failing =
        appIdUrl -> {
          calls.incrementAndGet();
          throw new IOException("boom");
        };
    TrustedFacetsAppIdVerifier verifier = new TrustedFacetsAppIdVerifier(failing);

    try {
      verifier.isAuthorizedFacet(APP_ID, TRUSTED_FACET);
      fail("Expected IOException to propagate");
    } catch (IOException expected) {
      // expected
    }

    // A failed fetch must not be cached, so a retry hits the transport again.
    try {
      verifier.isAuthorizedFacet(APP_ID, TRUSTED_FACET);
      fail("Expected IOException to propagate");
    } catch (IOException expected) {
      // expected
    }
    assertEquals(2, calls.get());
  }

  @Test
  public void parsesAllTrustedFacetIds() throws Exception {
    assertTrue(
        TrustedFacetsAppIdVerifier.parseTrustedFacetIds(DOCUMENT)
            .contains("https://login.example.com"));
    assertTrue(TrustedFacetsAppIdVerifier.parseTrustedFacetIds(DOCUMENT).contains(TRUSTED_FACET));
  }

  @Test
  public void malformedDocumentYieldsNoFacets() throws Exception {
    assertTrue(TrustedFacetsAppIdVerifier.parseTrustedFacetIds("{}").isEmpty());
    assertTrue(
        TrustedFacetsAppIdVerifier.parseTrustedFacetIds("{\"trustedFacets\":\"nope\"}").isEmpty());
    assertTrue(
        TrustedFacetsAppIdVerifier.parseTrustedFacetIds("{\"trustedFacets\":[{\"ids\":[1,2,3]}]}")
            .isEmpty());
  }
}

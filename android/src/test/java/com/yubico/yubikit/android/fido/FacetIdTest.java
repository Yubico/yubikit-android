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
package com.yubico.yubikit.android.fido;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import android.content.pm.Signature;
import androidx.test.ext.junit.runners.AndroidJUnit4;
import java.security.MessageDigest;
import java.util.Base64;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;

@RunWith(AndroidJUnit4.class)
@Config(manifest = Config.NONE)
public class FacetIdTest {

  // Arbitrary bytes standing in for a signing certificate's DER encoding; FacetId only hashes them.
  private static final byte[] CERT = {
    0x30, 0x0d, 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01
  };

  @Test
  public void facetIdIsSha256Base64UrlOfSigningCertificate() throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(CERT);
    String expected =
        "android:apk-key-hash:" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest);

    assertEquals(expected, FacetId.facetIdFromSignature(new Signature(CERT)));
  }

  @Test
  public void facetIdHasExpectedFormat() {
    String facetId = FacetId.facetIdFromSignature(new Signature(CERT));

    assertTrue(facetId.startsWith("android:apk-key-hash:"));
    // base64url alphabet only, no padding.
    String hash = facetId.substring("android:apk-key-hash:".length());
    assertTrue(hash.matches("[A-Za-z0-9_-]+"));
  }
}

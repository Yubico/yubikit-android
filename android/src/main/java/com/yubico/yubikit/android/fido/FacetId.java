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

import android.content.Context;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.content.pm.SigningInfo;
import android.os.Build;
import android.util.Base64;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Computes the Android FacetID of an application for use with the legacy U2F {@code appid} and
 * {@code appidExclude} WebAuthn extensions.
 *
 * <p>An Android FacetID has the form {@code android:apk-key-hash:<hash>}, where {@code <hash>} is
 * the base64url (no padding) encoding of the SHA-256 digest of the application's APK signing
 * certificate. This is the value that must appear in the TrustedFacets document referenced by an
 * AppID for the calling application to be authorized to use it.
 *
 * <p>Pass the result to {@code
 * Ctap2Client.getUserAgentConfiguration().setAppIdFacetId(FacetId.forSelf(context))}. The client
 * ships a default {@code TrustedFacetsAppIdVerifier}, so setting the FacetID is all that is
 * required to enable the extensions for the self-relying-party case.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-appid-and-facets-v1.2-ps-20170411.html">FIDO
 *     AppID and Facets</a>
 */
public final class FacetId {

  private static final String PREFIX = "android:apk-key-hash:";
  private static final int BASE64_FLAGS = Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP;

  private FacetId() {}

  /**
   * Computes the FacetID of the calling application itself.
   *
   * @param context an application or activity context.
   * @return the {@code android:apk-key-hash:<hash>} FacetID of this application.
   * @throws IllegalStateException if the application's own signing information cannot be read.
   */
  public static String forSelf(Context context) {
    try {
      return forPackage(context, context.getPackageName());
    } catch (PackageManager.NameNotFoundException e) {
      // The running application's own package always exists.
      throw new IllegalStateException("Unable to read own signing information", e);
    }
  }

  /**
   * Computes the FacetID of another installed application, identified by package name. This is
   * intended for credential-provider style callers that act on behalf of a separate calling app.
   *
   * @param context an application or activity context.
   * @param packageName the package name of the calling application.
   * @return the {@code android:apk-key-hash:<hash>} FacetID of the given application.
   * @throws PackageManager.NameNotFoundException if no application with the given package name is
   *     installed.
   */
  public static String forCallingApp(Context context, String packageName)
      throws PackageManager.NameNotFoundException {
    return forPackage(context, packageName);
  }

  private static String forPackage(Context context, String packageName)
      throws PackageManager.NameNotFoundException {
    Signature[] signatures = getSignatures(context.getPackageManager(), packageName);
    if (signatures == null || signatures.length == 0) {
      throw new IllegalStateException("No signing certificate found for " + packageName);
    }
    // The first signing certificate identifies the application. Apps signed by multiple
    // certificates
    // may publish additional FacetIDs; those integrators should supply the specific FacetID they
    // need rather than relying on this convenience.
    return facetIdFromSignature(signatures[0]);
  }

  @SuppressWarnings(
      "deprecation") // GET_SIGNATURES / PackageInfo.signatures used only below API 28.
  private static Signature[] getSignatures(PackageManager pm, String packageName)
      throws PackageManager.NameNotFoundException {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
      PackageInfo info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES);
      SigningInfo signingInfo = info.signingInfo;
      if (signingInfo == null) {
        return new Signature[0];
      }
      // The certificate(s) currently used to sign the APK. (getSigningCertificateHistory() would
      // instead return the rotation history, whose first entry may be a retired certificate.)
      return signingInfo.getApkContentsSigners();
    }
    PackageInfo info = pm.getPackageInfo(packageName, PackageManager.GET_SIGNATURES);
    return info.signatures;
  }

  static String facetIdFromSignature(Signature signature) {
    try {
      byte[] digest = MessageDigest.getInstance("SHA-256").digest(signature.toByteArray());
      return PREFIX + Base64.encodeToString(digest, BASE64_FLAGS);
    } catch (NoSuchAlgorithmException e) {
      // SHA-256 is a required algorithm on every Android platform.
      throw new IllegalStateException("SHA-256 not available", e);
    }
  }
}

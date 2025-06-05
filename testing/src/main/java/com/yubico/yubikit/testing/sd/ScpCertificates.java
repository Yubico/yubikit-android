/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.testing.sd;

import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nullable;

class ScpCertificates {
  @Nullable final X509Certificate ca;
  final List<X509Certificate> bundle;
  @Nullable final X509Certificate leaf;

  ScpCertificates(
      @Nullable X509Certificate ca, List<X509Certificate> bundle, @Nullable X509Certificate leaf) {
    this.ca = ca;
    this.bundle = bundle;
    this.leaf = leaf;
  }

  static ScpCertificates from(@Nullable List<X509Certificate> certificates) {
    if (certificates == null) {
      return new ScpCertificates(null, Collections.emptyList(), null);
    }

    X509Certificate ca = null;
    BigInteger seenSerial = null;

    // order certificates with the Root CA on top
    List<X509Certificate> ordered = new ArrayList<>();
    ordered.add(certificates.get(0));
    certificates.remove(0);

    while (!certificates.isEmpty()) {
      X509Certificate head = ordered.get(0);
      X509Certificate tail = ordered.get(ordered.size() - 1);
      X509Certificate cert = certificates.get(0);
      certificates.remove(0);

      if (isIssuedBy(cert, cert)) {
        ordered.add(0, cert);
        ca = ordered.get(0);
        continue;
      }

      if (isIssuedBy(cert, tail)) {
        ordered.add(cert);
        continue;
      }

      if (isIssuedBy(head, cert)) {
        ordered.add(0, cert);
        continue;
      }

      if (seenSerial != null && cert.getSerialNumber().equals(seenSerial)) {
        fail("Cannot decide the order of " + cert + " in " + ordered);
      }

      // this cert could not be ordered, try to process rest of certificates
      // but if you see this cert again fail because the cert chain is not complete
      certificates.add(cert);
      seenSerial = cert.getSerialNumber();
    }

    // find ca and leaf
    if (ca != null) {
      ordered.remove(0);
    }

    X509Certificate leaf = null;
    if (!ordered.isEmpty()) {
      X509Certificate lastCert = ordered.get(ordered.size() - 1);
      final boolean[] keyUsage = lastCert.getKeyUsage();
      if (keyUsage != null && keyUsage[4]) {
        leaf = lastCert;
        ordered.remove(leaf);
      }
    }

    return new ScpCertificates(ca, ordered, leaf);
  }

  /**
   * @param subjectCert the certificate which we test if it is issued by the issuerCert
   * @param issuerCert the certificate which should issue the subjectCertificate
   * @return true if the subject certificate is issued by the issuer certificate
   */
  private static boolean isIssuedBy(X509Certificate subjectCert, X509Certificate issuerCert) {
    return subjectCert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal());
  }
}

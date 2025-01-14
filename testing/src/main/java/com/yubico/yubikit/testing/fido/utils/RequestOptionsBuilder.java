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

package com.yubico.yubikit.testing.fido.utils;

import static com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType.PUBLIC_KEY;

import com.yubico.yubikit.fido.webauthn.Extensions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javax.annotation.Nullable;

public class RequestOptionsBuilder {
  @Nullable Extensions extensions = null;
  @Nullable List<PublicKeyCredentialDescriptor> allowedCredentials = null;

  public RequestOptionsBuilder extensions(@Nullable Map<String, ?> extensions) {
    this.extensions = extensions == null ? null : Extensions.fromMap(extensions);
    return this;
  }

  public RequestOptionsBuilder allowedCredentials(byte[]... allowedCredentials) {
    this.allowedCredentials =
        allowedCredentials.length > 0
            ? Arrays.stream(allowedCredentials)
                .map(id -> new PublicKeyCredentialDescriptor(PUBLIC_KEY, id))
                .collect(Collectors.toList())
            : null;
    return this;
  }

  public RequestOptionsBuilder allowedCredentials(PublicKeyCredential... allowedCredentials) {
    this.allowedCredentials =
        allowedCredentials.length > 0
            ? Arrays.stream(allowedCredentials)
                .map(
                    publicKeyCredential ->
                        new PublicKeyCredentialDescriptor(
                            PUBLIC_KEY, publicKeyCredential.getRawId()))
                .collect(Collectors.toList())
            : null;
    return this;
  }

  public RequestOptionsBuilder allowedCredentials(
      PublicKeyCredentialDescriptor... allowedCredentials) {
    this.allowedCredentials =
        allowedCredentials.length > 0 ? Arrays.asList(allowedCredentials) : null;
    return this;
  }

  public RequestOptionsBuilder allowedCredentials(
      List<PublicKeyCredentialDescriptor> allowedCredentials) {
    this.allowedCredentials = allowedCredentials;
    return this;
  }

  public PublicKeyCredentialRequestOptions build() {

    return new PublicKeyCredentialRequestOptions(
        TestData.CHALLENGE, (long) 90000, TestData.RP_ID, allowedCredentials, null, extensions);
  }
}

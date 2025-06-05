/*
 * Copyright (C) 2020-2023 Yubico.
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

package com.yubico.yubikit.fido.webauthn;

import static com.yubico.yubikit.fido.webauthn.SerializationUtils.deserializeBytes;
import static com.yubico.yubikit.fido.webauthn.SerializationUtils.serializeBytes;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

public class PublicKeyCredentialRequestOptions {
  private static final String CHALLENGE = "challenge";
  private static final String TIMEOUT = "timeout";
  private static final String RP_ID = "rpId";
  private static final String ALLOW_CREDENTIALS = "allowCredentials";
  private static final String USER_VERIFICATION = "userVerification";
  private static final String EXTENSIONS = "extensions";

  private final byte[] challenge;
  @Nullable private final Long timeout;
  @Nullable private final String rpId;
  private final List<PublicKeyCredentialDescriptor> allowCredentials;
  private final String userVerification;
  @Nullable private final Extensions extensions;

  public PublicKeyCredentialRequestOptions(
      byte[] challenge,
      @Nullable Long timeout,
      @Nullable String rpId,
      @Nullable List<PublicKeyCredentialDescriptor> allowCredentials,
      @Nullable String userVerification,
      @Nullable Extensions extensions) {
    this.challenge = challenge;
    this.timeout = timeout;
    this.rpId = rpId;
    this.allowCredentials = allowCredentials != null ? allowCredentials : Collections.emptyList();
    this.userVerification =
        userVerification != null ? userVerification : UserVerificationRequirement.PREFERRED;
    this.extensions = extensions;
  }

  public byte[] getChallenge() {
    return challenge;
  }

  public @Nullable Long getTimeout() {
    return timeout;
  }

  @Nullable
  public String getRpId() {
    return rpId;
  }

  public List<PublicKeyCredentialDescriptor> getAllowCredentials() {
    return allowCredentials;
  }

  public String getUserVerification() {
    return userVerification;
  }

  @Nullable
  public Extensions getExtensions() {
    return extensions;
  }

  public Map<String, ?> toMap(SerializationType serializationType) {
    Map<String, Object> map = new HashMap<>();
    map.put(CHALLENGE, serializeBytes(challenge, serializationType));
    if (timeout != null) {
      map.put(TIMEOUT, timeout);
    }
    if (rpId != null) {
      map.put(RP_ID, rpId);
    }
    List<Map<String, ?>> allowCredentialsList = new ArrayList<>();
    for (PublicKeyCredentialDescriptor cred : allowCredentials) {
      allowCredentialsList.add(cred.toMap(serializationType));
    }
    map.put(ALLOW_CREDENTIALS, allowCredentialsList);
    map.put(USER_VERIFICATION, userVerification);
    if (extensions != null) {
      map.put(EXTENSIONS, extensions);
    }
    return map;
  }

  @SuppressWarnings("unchecked")
  public static PublicKeyCredentialRequestOptions fromMap(
      Map<String, ?> map, SerializationType serializationType) {
    List<PublicKeyCredentialDescriptor> allowCredentials = null;
    List<Map<String, ?>> allowCredentialsList = (List<Map<String, ?>>) map.get(ALLOW_CREDENTIALS);
    if (allowCredentialsList != null) {
      allowCredentials = new ArrayList<>();
      for (Map<String, ?> cred : allowCredentialsList) {
        allowCredentials.add(PublicKeyCredentialDescriptor.fromMap(cred, serializationType));
      }
    }

    Number timeout = ((Number) map.get(TIMEOUT));

    return new PublicKeyCredentialRequestOptions(
        deserializeBytes(Objects.requireNonNull(map.get(CHALLENGE)), serializationType),
        timeout == null ? null : timeout.longValue(),
        (String) map.get(RP_ID),
        allowCredentials,
        (String) map.get(USER_VERIFICATION),
        Extensions.fromMap((Map<String, ?>) map.get(EXTENSIONS)));
  }

  public static PublicKeyCredentialRequestOptions fromMap(Map<String, ?> map) {
    return fromMap(map, SerializationType.DEFAULT);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    PublicKeyCredentialRequestOptions that = (PublicKeyCredentialRequestOptions) o;

    if (!Arrays.equals(challenge, that.challenge)) return false;
    if (!Objects.equals(timeout, that.timeout)) return false;
    if (!Objects.equals(rpId, that.rpId)) return false;
    if (!allowCredentials.equals(that.allowCredentials)) return false;
    if (!userVerification.equals(that.userVerification)) return false;
    return Objects.equals(extensions, that.extensions);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(challenge);
    result = 31 * result + (timeout != null ? timeout.hashCode() : 0);
    result = 31 * result + (rpId != null ? rpId.hashCode() : 0);
    result = 31 * result + allowCredentials.hashCode();
    result = 31 * result + userVerification.hashCode();
    result = 31 * result + (extensions != null ? extensions.hashCode() : 0);
    return result;
  }
}

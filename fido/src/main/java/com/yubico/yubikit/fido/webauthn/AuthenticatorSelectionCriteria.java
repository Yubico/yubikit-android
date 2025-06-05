/*
 * Copyright (C) 2020-2024 Yubico.
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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

public class AuthenticatorSelectionCriteria {
  private static final String AUTHENTICATOR_ATTACHMENT = "authenticatorAttachment";
  private static final String RESIDENT_KEY = "residentKey";
  private static final String REQUIRE_RESIDENT_KEY = "requireResidentKey";
  private static final String USER_VERIFICATION = "userVerification";

  @Nullable private final String authenticatorAttachment;
  @Nullable private final String residentKey;
  private final boolean requireResidentKey;
  private final String userVerification;

  public AuthenticatorSelectionCriteria(
      @Nullable String authenticatorAttachment,
      @Nullable String residentKey,
      @Nullable String userVerification) {
    this.authenticatorAttachment = authenticatorAttachment;
    this.residentKey = residentKey;
    this.requireResidentKey = ResidentKeyRequirement.REQUIRED.equals(residentKey);
    this.userVerification =
        userVerification != null ? userVerification : UserVerificationRequirement.PREFERRED;
  }

  @Nullable
  public String getAuthenticatorAttachment() {
    return authenticatorAttachment;
  }

  @Nullable
  public String getResidentKey() {
    return residentKey;
  }

  public String getUserVerification() {
    return userVerification;
  }

  public Map<String, ?> toMap(@SuppressWarnings("unused") SerializationType serializationType) {
    Map<String, Object> map = new HashMap<>();
    if (authenticatorAttachment != null) {
      map.put(AUTHENTICATOR_ATTACHMENT, authenticatorAttachment);
    }
    if (residentKey != null) {
      map.put(RESIDENT_KEY, residentKey);
    }
    map.put(REQUIRE_RESIDENT_KEY, requireResidentKey);
    map.put(USER_VERIFICATION, userVerification);
    return map;
  }

  public static AuthenticatorSelectionCriteria fromMap(
      Map<String, ?> map, @SuppressWarnings("unused") SerializationType serializationType) {
    String residentKeyRequirement = (String) map.get(RESIDENT_KEY);
    if (residentKeyRequirement == null) {
      // Backwards compatibility with WebAuthn level 1
      if (Boolean.TRUE.equals(map.get(REQUIRE_RESIDENT_KEY))) {
        residentKeyRequirement = ResidentKeyRequirement.REQUIRED;
      } else {
        residentKeyRequirement = ResidentKeyRequirement.DISCOURAGED;
      }
    }
    return new AuthenticatorSelectionCriteria(
        (String) map.get(AUTHENTICATOR_ATTACHMENT),
        residentKeyRequirement,
        (String) map.get(USER_VERIFICATION));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    AuthenticatorSelectionCriteria that = (AuthenticatorSelectionCriteria) o;

    if (requireResidentKey != that.requireResidentKey) return false;
    if (!Objects.equals(authenticatorAttachment, that.authenticatorAttachment)) return false;
    if (!Objects.equals(residentKey, that.residentKey)) return false;
    return userVerification.equals(that.userVerification);
  }

  @Override
  public int hashCode() {
    int result = authenticatorAttachment != null ? authenticatorAttachment.hashCode() : 0;
    result = 31 * result + (residentKey != null ? residentKey.hashCode() : 0);
    result = 31 * result + (requireResidentKey ? 1 : 0);
    result = 31 * result + userVerification.hashCode();
    return result;
  }
}

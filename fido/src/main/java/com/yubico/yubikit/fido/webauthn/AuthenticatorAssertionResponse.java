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

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

public class AuthenticatorAssertionResponse extends AuthenticatorResponse {
  public static final String AUTHENTICATOR_DATA = "authenticatorData";
  public static final String SIGNATURE = "signature";
  public static final String USER_HANDLE = "userHandle";

  private final byte[] authenticatorData;
  private final byte[] signature;
  @Nullable private final byte[] userHandle;

  public AuthenticatorAssertionResponse(
      byte[] clientDataJson,
      byte[] authenticatorData,
      byte[] signature,
      @Nullable byte[] userHandle) {
    super(clientDataJson);
    this.authenticatorData = authenticatorData;
    this.signature = signature;
    this.userHandle = userHandle;
  }

  public byte[] getAuthenticatorData() {
    return authenticatorData;
  }

  public byte[] getSignature() {
    return signature;
  }

  @Nullable
  public byte[] getUserHandle() {
    return userHandle;
  }

  @Override
  public Map<String, ?> toMap(SerializationType serializationType) {
    Map<String, Object> map = new HashMap<>();
    map.put(CLIENT_DATA_JSON, serializeBytes(getClientDataJson(), serializationType));
    map.put(AUTHENTICATOR_DATA, serializeBytes(authenticatorData, serializationType));
    map.put(SIGNATURE, serializeBytes(signature, serializationType));
    if (userHandle != null) {
      map.put(USER_HANDLE, serializeBytes(userHandle, serializationType));
    }
    return map;
  }

  public static AuthenticatorAssertionResponse fromMap(
      Map<String, ?> map, SerializationType serializationType) {
    return new AuthenticatorAssertionResponse(
        deserializeBytes(Objects.requireNonNull(map.get(CLIENT_DATA_JSON)), serializationType),
        deserializeBytes(Objects.requireNonNull(map.get(AUTHENTICATOR_DATA)), serializationType),
        deserializeBytes(Objects.requireNonNull(map.get(SIGNATURE)), serializationType),
        deserializeBytes(map.get(USER_HANDLE), serializationType));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    AuthenticatorAssertionResponse that = (AuthenticatorAssertionResponse) o;

    if (!Arrays.equals(authenticatorData, that.authenticatorData)) return false;
    if (!Arrays.equals(signature, that.signature)) return false;
    return Arrays.equals(userHandle, that.userHandle);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(authenticatorData);
    result = 31 * result + Arrays.hashCode(signature);
    result = 31 * result + Arrays.hashCode(userHandle);
    return result;
  }
}

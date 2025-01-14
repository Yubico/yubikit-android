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

public class PublicKeyCredentialUserEntity extends PublicKeyCredentialEntity {
  public static final String ID = "id";
  public static final String DISPLAY_NAME = "displayName";

  private final byte[] id;
  private final String displayName;

  public PublicKeyCredentialUserEntity(String name, byte[] id, String displayName) {
    super(name);
    this.id = id;
    this.displayName = displayName;
  }

  public byte[] getId() {
    return id;
  }

  public String getDisplayName() {
    return displayName;
  }

  public Map<String, ?> toMap(SerializationType serializationType) {
    Map<String, Object> map = new HashMap<>();
    map.put(NAME, getName());
    map.put(ID, serializeBytes(id, serializationType));
    map.put(DISPLAY_NAME, displayName);
    return map;
  }

  public static PublicKeyCredentialUserEntity fromMap(
      Map<String, ?> map, SerializationType serializationType) {
    return new PublicKeyCredentialUserEntity(
        Objects.requireNonNull((String) map.get(NAME)),
        deserializeBytes(Objects.requireNonNull(map.get(ID)), serializationType),
        Objects.requireNonNull((String) map.get(DISPLAY_NAME)));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    PublicKeyCredentialUserEntity that = (PublicKeyCredentialUserEntity) o;

    if (!Arrays.equals(id, that.id)) return false;
    return displayName.equals(that.displayName);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(id);
    result = 31 * result + displayName.hashCode();
    return result;
  }
}

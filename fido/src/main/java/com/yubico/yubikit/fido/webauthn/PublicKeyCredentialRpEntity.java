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

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

public class PublicKeyCredentialRpEntity extends PublicKeyCredentialEntity {
  private static final String ID = "id";
  @Nullable private final String id;

  public PublicKeyCredentialRpEntity(String name, @Nullable String id) {
    super(name);
    this.id = id;
  }

  @Nullable
  public String getId() {
    return id;
  }

  public Map<String, ?> toMap(@SuppressWarnings("unused") SerializationType serializationType) {
    Map<String, Object> map = new HashMap<>();
    map.put(NAME, getName());
    if (id != null) {
      map.put(ID, id);
    }
    return map;
  }

  public static PublicKeyCredentialRpEntity fromMap(
      Map<String, ?> map, @SuppressWarnings("unused") SerializationType serializationType) {
    return new PublicKeyCredentialRpEntity(
        Objects.requireNonNull((String) map.get(NAME)), (String) map.get(ID));
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    PublicKeyCredentialRpEntity that = (PublicKeyCredentialRpEntity) o;

    return Objects.equals(id, that.id);
  }

  @Override
  public int hashCode() {
    return id != null ? id.hashCode() : 0;
  }
}

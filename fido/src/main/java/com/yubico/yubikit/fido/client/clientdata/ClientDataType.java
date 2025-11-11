/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.fido.client.clientdata;

import java.util.Objects;

/**
 * Extensible value object representing WebAuthn clientDataJSON "type". Provides predefined
 * constants plus factory for custom future values.
 */
public final class ClientDataType {
  public static final ClientDataType CREATE = new ClientDataType("webauthn.create");
  public static final ClientDataType GET = new ClientDataType("webauthn.get");

  private final String value;

  private ClientDataType(String value) {
    this.value = value;
  }

  public static ClientDataType of(String value) {
    return new ClientDataType(Objects.requireNonNull(value, "value"));
  }

  public String jsonValue() {
    return value;
  }

  @Override
  public String toString() {
    return value;
  }

  @Override
  public boolean equals(Object o) {
    return (o instanceof ClientDataType) && value.equals(((ClientDataType) o).value);
  }

  @Override
  public int hashCode() {
    return value.hashCode();
  }
}

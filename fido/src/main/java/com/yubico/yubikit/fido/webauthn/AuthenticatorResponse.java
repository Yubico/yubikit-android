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

import java.util.Map;

/**
 * @see <a
 *     href="https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#iface-authenticatorresponse">AuthenticatorResponse</a>
 */
public abstract class AuthenticatorResponse {
  static final String CLIENT_DATA_JSON = "clientDataJSON";

  private final byte[] clientDataJson;

  AuthenticatorResponse(byte[] clientDataJson) {
    this.clientDataJson = clientDataJson;
  }

  public byte[] getClientDataJson() {
    return clientDataJson;
  }

  public abstract Map<String, ?> toMap(SerializationType serializationType);
}

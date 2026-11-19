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

package com.yubico.yubikit.fido.webauthn;

/**
 * Values for the {@code hints} member of the creation and request options.
 *
 * <p>Hints are advisory: a client may ignore them, and must ignore values it does not recognize.
 *
 * @see <a href="https://www.w3.org/TR/webauthn-3/#enum-hints">PublicKeyCredentialHint</a>
 */
@SuppressWarnings("unused")
public class PublicKeyCredentialHint {
  public static final String SECURITY_KEY = "security-key";
  public static final String CLIENT_DEVICE = "client-device";
  public static final String HYBRID = "hybrid";
}

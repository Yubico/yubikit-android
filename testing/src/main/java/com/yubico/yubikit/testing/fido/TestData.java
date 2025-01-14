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

package com.yubico.yubikit.testing.fido;

import com.squareup.moshi.Moshi;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import java.nio.charset.StandardCharsets;
import org.bouncycastle.util.encoders.Base64;

class TestData {

  static class ClientData {
    @SuppressWarnings("unused")
    public final String type;

    @SuppressWarnings("unused")
    public final String origin;

    @SuppressWarnings("unused")
    public final String challenge;

    @SuppressWarnings("unused")
    public final String androidPackageName;

    public ClientData(String type, String origin, byte[] challenge, String androidPackageName) {
      this.type = type;
      this.origin = origin;
      this.challenge = Base64.toBase64String(challenge);
      this.androidPackageName = androidPackageName;
    }
  }

  public static final char[] PIN = "11234567".toCharArray();
  public static final char[] OTHER_PIN = "11231234".toCharArray();

  public static final String RP_ID = "example.com";
  public static final String RP_NAME = "Example Company";
  public static final PublicKeyCredentialRpEntity RP =
      new PublicKeyCredentialRpEntity(RP_NAME, RP_ID);

  public static final String USER_NAME = "john.doe@example.com";
  public static final byte[] USER_ID = USER_NAME.getBytes(StandardCharsets.UTF_8);
  public static final String USER_DISPLAY_NAME = "John Doe";
  public static final PublicKeyCredentialUserEntity USER =
      new PublicKeyCredentialUserEntity(USER_NAME, USER_ID, USER_DISPLAY_NAME);

  public static final String ORIGIN = "https://" + RP_ID;
  public static final byte[] CHALLENGE =
      new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};

  private static final String PACKAGE_NAME = "TestPackage";

  public static final byte[] CLIENT_DATA_JSON_CREATE =
      new Moshi.Builder()
          .build()
          .adapter(ClientData.class)
          .toJson(new ClientData("webauthn.create", ORIGIN, CHALLENGE, PACKAGE_NAME))
          .getBytes(StandardCharsets.UTF_8);

  public static final byte[] CLIENT_DATA_JSON_GET =
      new Moshi.Builder()
          .build()
          .adapter(ClientData.class)
          .toJson(new ClientData("webauthn.get", ORIGIN, CHALLENGE, PACKAGE_NAME))
          .getBytes(StandardCharsets.UTF_8);

  public static final byte[] CLIENT_DATA_HASH =
      new byte[] {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
        12, 13, 14, 15
      };

  public static final PublicKeyCredentialParameters PUB_KEY_CRED_PARAMS_ES256 =
      new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -7);

  public static final PublicKeyCredentialParameters PUB_KEY_CRED_PARAMS_EDDSA =
      new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -8);
}

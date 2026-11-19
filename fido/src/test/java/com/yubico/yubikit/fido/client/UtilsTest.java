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

package com.yubico.yubikit.fido.client;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;

import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import java.util.Collections;
import java.util.List;
import org.junit.Test;

public class UtilsTest {

  private static PublicKeyCredentialCreationOptions options(
      List<PublicKeyCredentialParameters> params) {
    return new PublicKeyCredentialCreationOptions(
        new PublicKeyCredentialRpEntity("Example", "example.com"),
        new PublicKeyCredentialUserEntity("user", new byte[] {1}, "A User"),
        new byte[32],
        params,
        null,
        null,
        null,
        null,
        null);
  }

  @Test
  public void emptyPubKeyCredParamsDefaultToEs256ThenRs256() {
    List<PublicKeyCredentialParameters> params =
        Utils.getPubKeyCredParams(options(Collections.emptyList()));

    assertEquals(2, params.size());
    assertEquals(PublicKeyCredentialType.PUBLIC_KEY, params.get(0).getType());
    assertEquals(-7, params.get(0).getAlg());
    assertEquals(PublicKeyCredentialType.PUBLIC_KEY, params.get(1).getType());
    assertEquals(-257, params.get(1).getAlg());
  }

  @Test
  public void nonEmptyPubKeyCredParamsArePassedThrough() {
    List<PublicKeyCredentialParameters> requested =
        Collections.singletonList(
            new PublicKeyCredentialParameters(PublicKeyCredentialType.PUBLIC_KEY, -8));

    assertSame(requested, Utils.getPubKeyCredParams(options(requested)));
  }
}

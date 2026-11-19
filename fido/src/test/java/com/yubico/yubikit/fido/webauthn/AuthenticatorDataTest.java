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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.nio.ByteBuffer;
import org.junit.Test;

public class AuthenticatorDataTest {

  private static AuthenticatorData parse(int flags) {
    ByteBuffer buffer = ByteBuffer.allocate(32 + 1 + 4);
    buffer.put(new byte[32]).put((byte) flags).putInt(0);
    buffer.flip();
    return AuthenticatorData.parseFrom(buffer);
  }

  @Test
  public void backupFlagsAreReadFromBits3And4() {
    AuthenticatorData none = parse(0x01);
    assertFalse(none.isBe());
    assertFalse(none.isBs());

    AuthenticatorData eligible = parse(0x01 | 0x08);
    assertTrue(eligible.isBe());
    assertFalse(eligible.isBs());

    AuthenticatorData backedUp = parse(0x01 | 0x08 | 0x10);
    assertTrue(backedUp.isBe());
    assertTrue(backedUp.isBs());
  }

  @Test
  public void backupFlagsDoNotAliasNeighbouringFlags() {
    AuthenticatorData others = parse(0x01 | 0x04);
    assertTrue(others.isUp());
    assertTrue(others.isUv());
    assertFalse(others.isBe());
    assertFalse(others.isBs());
  }
}

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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.ClientExtensionResults;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;
import org.junit.Test;

public class MultipleAssertionsAvailableTest {

  private static Map<String, Object> user(
      byte[] id, @Nullable String name, @Nullable String displayName) {
    Map<String, Object> user = new HashMap<>();
    user.put("id", id);
    if (name != null) user.put("name", name);
    if (displayName != null) user.put("displayName", displayName);
    return user;
  }

  @SafeVarargs
  private static MultipleAssertionsAvailable available(@Nullable Map<String, ?>... users) {
    List<Pair<Ctap2Session.AssertionData, ClientExtensionResults>> assertions = new ArrayList<>();
    for (Map<String, ?> user : users) {
      Ctap2Session.AssertionData data = mock(Ctap2Session.AssertionData.class);
      when(data.getUser()).thenAnswer(invocation -> user);
      assertions.add(new Pair<>(data, new ClientExtensionResults()));
    }
    return new MultipleAssertionsAvailable(new byte[0], assertions);
  }

  @Test
  public void getUsersWithAllFields() throws Throwable {
    List<PublicKeyCredentialUserEntity> users =
        available(user(new byte[] {1}, "alice", "Alice A."), user(new byte[] {2}, "bob", "Bob B."))
            .getUsers();
    assertEquals(2, users.size());
    assertEquals("alice", users.get(0).getName());
    assertEquals("Alice A.", users.get(0).getDisplayName());
    assertArrayEquals(new byte[] {2}, users.get(1).getId());
  }

  @Test
  public void getUsersWithoutDisplayNameFallsBackToName() throws Throwable {
    // A YubiKey holding two discoverable credentials for one RP returns id + name only.
    List<PublicKeyCredentialUserEntity> users =
        available(user(new byte[] {1}, "fridolin", null), user(new byte[] {2}, "admin", null))
            .getUsers();
    assertEquals(2, users.size());
    assertEquals("fridolin", users.get(0).getDisplayName());
    assertEquals("admin", users.get(1).getDisplayName());
  }

  @Test
  public void getUsersWithEmptyDisplayNameFallsBackToName() throws Throwable {
    List<PublicKeyCredentialUserEntity> users =
        available(user(new byte[] {1}, "fridolin", ""), user(new byte[] {2}, "admin", ""))
            .getUsers();
    assertEquals("fridolin", users.get(0).getDisplayName());
    assertEquals("admin", users.get(1).getDisplayName());
  }

  @Test
  public void getUsersWithIdOnly() throws Throwable {
    List<PublicKeyCredentialUserEntity> users =
        available(user(new byte[] {1}, null, null), user(new byte[] {2}, null, null)).getUsers();
    assertEquals(2, users.size());
    assertEquals("", users.get(0).getName());
    assertEquals("", users.get(0).getDisplayName());
    assertArrayEquals(new byte[] {1}, users.get(0).getId());
  }

  @Test
  public void getUsersWithoutUserThrows() {
    assertThrows(
        UserInformationNotAvailableError.class,
        () -> available(user(new byte[] {1}, "alice", null), null).getUsers());
  }
}

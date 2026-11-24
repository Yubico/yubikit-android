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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class CredentialManagerTest {

  private static CredentialManagement.CredentialData credential(byte[] credId, byte[] userId) {
    Map<String, Object> credentialId = new HashMap<>();
    credentialId.put(PublicKeyCredentialDescriptor.TYPE, "public-key");
    credentialId.put(PublicKeyCredentialDescriptor.ID, credId);

    Map<String, ?> user = Collections.singletonMap(PublicKeyCredentialUserEntity.ID, userId);

    CredentialManagement.CredentialData data = mock(CredentialManagement.CredentialData.class);
    when(data.getCredentialId()).thenAnswer(invocation -> credentialId);
    when(data.getUser()).thenAnswer(invocation -> user);
    return data;
  }

  private static Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> list(
      CredentialManagement.CredentialData... credentials) throws Throwable {
    CredentialManagement management = mock(CredentialManagement.class);
    when(management.enumerateCredentials(any())).thenReturn(Arrays.asList(credentials));
    return new CredentialManager(management).getCredentials("example.com");
  }

  private static PublicKeyCredentialUserEntity userFor(
      Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> credentials, byte credId) {
    return credentials.get(new PublicKeyCredentialDescriptor("public-key", new byte[] {credId}));
  }

  @Test
  public void getCredentialsWithIdOnly() throws Throwable {
    Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> credentials =
        list(credential(new byte[] {1}, new byte[] {11}));
    assertEquals("", userFor(credentials, (byte) 1).getName());
    assertEquals("", userFor(credentials, (byte) 1).getDisplayName());
  }
}

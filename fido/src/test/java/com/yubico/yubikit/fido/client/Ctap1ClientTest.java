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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider;
import com.yubico.yubikit.fido.ctap.Ctap1Session;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.fido.webauthn.UserVerificationRequirement;
import java.io.IOException;
import java.util.Collections;
import org.junit.Test;

public class Ctap1ClientTest {
  private static final byte[] CREDENTIAL_ID = {1, 2, 3, 4};

  private final Ctap1Session session = mock(Ctap1Session.class);
  private final Ctap1Client client = new Ctap1Client(session);
  private final ClientDataProvider clientData = mock(ClientDataProvider.class);

  private PublicKeyCredentialRequestOptions options(String userVerification) {
    return new PublicKeyCredentialRequestOptions(
        new byte[32],
        null,
        null,
        Collections.singletonList(
            new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, CREDENTIAL_ID)),
        userVerification,
        null);
  }

  private PublicKeyCredential getAssertion(String userVerification) throws Exception {
    when(clientData.getHash()).thenReturn(new byte[32]);
    when(clientData.getClientDataJson()).thenReturn(new byte[] {'{', '}'});
    Ctap1Session.SignatureData signatureData = mock(Ctap1Session.SignatureData.class);
    when(signatureData.getSignature()).thenReturn(new byte[] {5, 6});
    when(session.authenticate(any(), any(), any(), anyBoolean())).thenReturn(signatureData);
    return client.getAssertion(clientData, options(userVerification), "example.com", null, null);
  }

  @Test
  public void requiredUserVerificationIsRejectedBeforeAuthenticating() throws Exception {
    ClientError error =
        assertThrows(ClientError.class, () -> getAssertion(UserVerificationRequirement.REQUIRED));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, error.getErrorCode());
    verify(session, never()).authenticate(any(), any(), any(), anyBoolean());
  }

  @Test
  public void preferredAndDiscouragedUserVerificationStillAuthenticate() throws Exception {
    for (String uv :
        new String[] {
          UserVerificationRequirement.PREFERRED, UserVerificationRequirement.DISCOURAGED, null
        }) {
      assertArrayEquals(CREDENTIAL_ID, getAssertion(uv).getRawId());
    }
  }

  @Test
  public void emptyPubKeyCredParamsDefaultToEs256AndRegister() throws Exception {
    when(clientData.getHash()).thenReturn(new byte[32]);
    when(session.register(any(), any())).thenThrow(new IOException("register reached"));
    PublicKeyCredentialCreationOptions options =
        new PublicKeyCredentialCreationOptions(
            new PublicKeyCredentialRpEntity("Example", "example.com"),
            new PublicKeyCredentialUserEntity("user", new byte[] {1}, "A User"),
            new byte[32],
            Collections.emptyList(),
            null,
            null,
            null,
            null,
            null);

    assertThrows(
        IOException.class,
        () -> client.makeCredential(clientData, options, "example.com", null, null, null));
    verify(session).register(any(), any());
  }
}

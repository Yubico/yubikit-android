/*
 * Copyright (C) 2024-2025 Yubico.
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

package com.yubico.yubikit.testing.fido.utils;

import static org.junit.Assert.assertNotNull;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.client.BasicWebAuthnClient;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.client.CredentialManager;
import com.yubico.yubikit.fido.client.MultipleAssertionsAvailable;
import com.yubico.yubikit.fido.client.extensions.Extension;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import javax.annotation.Nullable;

public class ClientHelper {
  final BasicWebAuthnClient client;
  @Nullable private char[] pin;

  public ClientHelper(Ctap2Session ctap) throws IOException, CommandException {
    this.pin = TestData.PIN;
    this.client = new BasicWebAuthnClient(ctap);
  }

  public ClientHelper(Ctap2Session ctap, List<Extension> extensions)
      throws IOException, CommandException {
    this.pin = TestData.PIN;
    this.client = new BasicWebAuthnClient(ctap, extensions);
  }

  public PublicKeyCredential makeCredential() throws IOException, CommandException, ClientError {
    return makeCredential(new CreationOptionsBuilder().build());
  }

  public PublicKeyCredential makeCredential(PublicKeyCredentialCreationOptions options)
      throws IOException, CommandException, ClientError {
    return client.makeCredential(
        TestData.CLIENT_DATA_JSON_CREATE, options, TestData.RP_ID, pin, null, null);
  }

  public PublicKeyCredential getAssertions(PublicKeyCredentialRequestOptions options)
      throws IOException, CommandException, ClientError, MultipleAssertionsAvailable {
    return client.getAssertion(TestData.CLIENT_DATA_JSON_GET, options, TestData.RP_ID, pin, null);
  }

  public void deleteCredentialsByIds(List<byte[]> credIds)
      throws IOException, CommandException, ClientError {
    try {
      assertNotNull("Pin cannot be null for delete credential", pin);
      CredentialManager credentialManager = client.getCredentialManager(pin);
      for (byte[] credId : credIds) {
        credentialManager.deleteCredential(
            new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, credId, null));
      }
    } catch (IllegalStateException ignored) {
      // credential manager might not be supported
    }
  }

  public void deleteCredentials(List<PublicKeyCredential> credentials)
      throws IOException, CommandException, ClientError {
    List<byte[]> credIds = new ArrayList<>();
    for (PublicKeyCredential credential : credentials) {
      credIds.add(credential.getRawId());
    }
    deleteCredentialsByIds(credIds);
  }

  public void deleteCredentials(PublicKeyCredential... credentials)
      throws IOException, CommandException, ClientError {
    List<byte[]> credIds = new ArrayList<>();
    for (PublicKeyCredential credential : credentials) {
      credIds.add(credential.getRawId());
    }
    deleteCredentialsByIds(credIds);
  }

  public ClientHelper withPin(@Nullable char[] pin) {
    this.pin = pin;
    return this;
  }
}

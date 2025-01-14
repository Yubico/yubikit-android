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

package com.yubico.yubikit.fido.client;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Provides management of resident key type credentials, which are stored on a YubiKey. An instance
 * of this class can be obtained by calling {@link
 * BasicWebAuthnClient#getCredentialManager(char[])}.
 */
@SuppressWarnings("unused")
public class CredentialManager {
  private final Map<String, byte[]> rpIdHashes = new HashMap<>();
  private final CredentialManagement credentialManagement;

  CredentialManager(CredentialManagement credentialManagement) {
    this.credentialManagement = credentialManagement;
  }

  /**
   * Get the number of credentials currently stored on the YubiKey.
   *
   * @return The total number of resident credentials existing on the authenticator.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @throws ClientError A higher level error.
   */
  public int getCredentialCount() throws IOException, CommandException, ClientError {
    try {
      return credentialManagement.getMetadata().getExistingResidentCredentialsCount();
    } catch (CtapException e) {
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Get a List of RP IDs for which this YubiKey has stored credentials.
   *
   * @return A list of RP IDs, which can be used to call {@link #getCredentials(String)}.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @throws ClientError A higher level error.
   */
  public List<String> getRpIdList() throws IOException, CommandException, ClientError {
    try {
      List<String> rpIds = new ArrayList<>();
      rpIdHashes.clear();
      for (CredentialManagement.RpData rpData : credentialManagement.enumerateRps()) {
        String rpId = (String) rpData.getRp().get("id");
        rpIdHashes.put(rpId, rpData.getRpIdHash());
        rpIds.add(rpId);
      }
      return rpIds;
    } catch (CtapException e) {
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Get resident key credentials stored for a particular RP.
   *
   * @param rpId The ID of the RP to get credentials for.
   * @return A mapping between {@link PublicKeyCredentialDescriptor}s to their associated {@link
   *     PublicKeyCredentialUserEntity}
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @throws ClientError A higher level error.
   */
  public Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> getCredentials(
      String rpId) throws IOException, CommandException, ClientError {
    try {
      Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> credentials =
          new HashMap<>();
      byte[] rpIdHash = rpIdHashes.get(rpId);
      if (rpIdHash == null) {
        rpIdHash = BasicWebAuthnClient.Utils.hash(rpId.getBytes(StandardCharsets.UTF_8));
      }

      for (CredentialManagement.CredentialData credData :
          credentialManagement.enumerateCredentials(rpIdHash)) {
        final Map<String, ?> credentialIdMap = credData.getCredentialId();
        credentials.put(
            PublicKeyCredentialDescriptor.fromMap(
                credData.getCredentialId(), SerializationType.CBOR),
            PublicKeyCredentialUserEntity.fromMap(credData.getUser(), SerializationType.CBOR));
      }

      return credentials;
    } catch (CtapException e) {
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Delete a stored credential from the YubiKey.
   *
   * @param credential A {@link PublicKeyCredentialDescriptor} which can be gotten from {@link
   *     #getCredentials(String)}.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @throws ClientError A higher level error.
   */
  public void deleteCredential(PublicKeyCredentialDescriptor credential)
      throws IOException, CommandException, ClientError {
    try {
      credentialManagement.deleteCredential(credential.toMap(SerializationType.CBOR));
    } catch (CtapException e) {
      throw ClientError.wrapCtapException(e);
    }
  }

  /**
   * Update user information associated to a credential. Only name and displayName can be changed.
   *
   * @param credential A {@link PublicKeyCredentialDescriptor} which can be gotten from {@link
   *     #getCredentials(String)}.
   * @param user A {@link PublicKeyCredentialUserEntity} containing updated data.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @throws ClientError A higher level error.
   * @throws UnsupportedOperationException If the authenticator does not support updating user
   *     information.
   */
  public void updateUserInformation(
      PublicKeyCredentialDescriptor credential, PublicKeyCredentialUserEntity user)
      throws IOException, CommandException, ClientError, UnsupportedOperationException {
    try {
      credentialManagement.updateUserInformation(
          credential.toMap(SerializationType.CBOR), user.toMap(SerializationType.CBOR));
    } catch (CtapException e) {
      throw ClientError.wrapCtapException(e);
    }
  }
}

/*
 * Copyright (C) 2020-2025 Yubico.
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

package com.yubico.yubikit.fido.ctap;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.fido.Cbor;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

/** Provides Credential management on the CTAP level. */
@SuppressWarnings("unused")
public class CredentialManagement {
  private static final byte CMD_GET_CREDS_METADATA = 0x01;
  private static final byte CMD_ENUMERATE_RPS_BEGIN = 0x02;
  private static final byte CMD_ENUMERATE_RPS_NEXT = 0x03;
  private static final byte CMD_ENUMERATE_CREDS_BEGIN = 0x04;
  private static final byte CMD_ENUMERATE_CREDS_NEXT = 0x05;
  private static final byte CMD_DELETE_CREDENTIAL = 0x06;
  private static final byte CMD_UPDATE_USER_INFORMATION = 0x07;

  private static final byte PARAM_RP_ID_HASH = 0x01;
  private static final byte PARAM_CREDENTIAL_ID = 0x02;
  private static final byte PARAM_USER = 0x03;

  private static final int RESULT_EXISTING_CRED_COUNT = 0x01;
  private static final int RESULT_MAX_REMAINING_COUNT = 0x02;
  private static final int RESULT_RP = 0x03;
  private static final int RESULT_RP_ID_HASH = 0x04;
  private static final int RESULT_TOTAL_RPS = 0x05;
  private static final int RESULT_USER = 0x06;
  private static final int RESULT_CREDENTIAL_ID = 0x07;
  private static final int RESULT_PUBLIC_KEY = 0x08;
  private static final int RESULT_TOTAL_CREDENTIALS = 0x09;
  private static final int RESULT_CRED_PROTECT = 0x0A;
  private static final int RESULT_LARGE_BLOB_KEY = 0x0B;

  private final Ctap2Session ctap;
  private final PinUvAuthProtocol pinUvAuth;
  private final byte[] pinUvToken;

  /**
   * Construct a new CredentialManagement object.
   *
   * @param ctap an active CTAP2 connection.
   * @param pinUvAuth the PIN/UV Auth protocol to use
   * @param pinUvToken a pinUvToken to be used, which must match the protocol and have the proper
   *     permissions
   */
  public CredentialManagement(Ctap2Session ctap, PinUvAuthProtocol pinUvAuth, byte[] pinUvToken) {
    if (!isSupported(ctap.getCachedInfo())) {
      throw new IllegalStateException("Credential manager not supported");
    }
    this.ctap = ctap;
    this.pinUvAuth = pinUvAuth;
    this.pinUvToken = pinUvToken;
  }

  public static boolean isSupported(Ctap2Session.InfoData info) {
    return supportsCredMgmt(info) || supportsCredentialMgmtPreview(info);
  }

  public static boolean isReadonlySupported(Ctap2Session.InfoData info) {
    return Boolean.TRUE.equals(info.getOptions().get("perCredMgmtRO"));
  }

  private static boolean supportsCredMgmt(Ctap2Session.InfoData info) {
    return Boolean.TRUE.equals(info.getOptions().get("credMgmt"));
  }

  private static boolean supportsCredentialMgmtPreview(Ctap2Session.InfoData info) {
    return info.getVersions().contains("FIDO_2_1_PRE")
        && Boolean.TRUE.equals(info.getOptions().get("credentialMgmtPreview"));
  }

  private Map<Integer, ?> call(
      byte subCommand, @Nullable Map<?, ?> subCommandParams, boolean authenticate)
      throws IOException, CommandException {
    byte[] pinUvAuthParam = null;
    if (authenticate) {
      ByteArrayOutputStream output = new ByteArrayOutputStream();
      output.write(subCommand);
      if (subCommandParams != null) {
        Cbor.encodeTo(output, subCommandParams);
      }
      pinUvAuthParam = pinUvAuth.authenticate(pinUvToken, output.toByteArray());
    }

    return ctap.credentialManagement(
        subCommand, subCommandParams, pinUvAuth.getVersion(), pinUvAuthParam);
  }

  /**
   * Get the underlying Pin/UV Auth protocol in use.
   *
   * @return the PinUvAuthProtocol in use
   */
  public PinUvAuthProtocol getPinUvAuth() {
    return pinUvAuth;
  }

  /**
   * Read metadata about credential management from the YubiKey.
   *
   * @return Metadata from the YubiKey.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   */
  public Metadata getMetadata() throws IOException, CommandException {
    Map<Integer, ?> data = call(CMD_GET_CREDS_METADATA, null, true);
    return new Metadata(
        Objects.requireNonNull((Integer) data.get(RESULT_EXISTING_CRED_COUNT)),
        Objects.requireNonNull((Integer) data.get(RESULT_MAX_REMAINING_COUNT)));
  }

  /**
   * Enumerate which RPs this YubiKey has credentials stored for.
   *
   * @return A list of RPs.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   */
  public List<RpData> enumerateRps() throws IOException, CommandException {
    List<RpData> list = new ArrayList<>();
    try {
      Map<Integer, ?> first = call(CMD_ENUMERATE_RPS_BEGIN, null, true);
      Integer nRps = (Integer) first.get(RESULT_TOTAL_RPS);

      if (nRps != null && nRps > 0) {
        list.add(RpData.fromData(first));
        for (int i = nRps; i > 1; i--) {
          list.add(RpData.fromData(call(CMD_ENUMERATE_RPS_NEXT, null, false)));
        }
      }
    } catch (CtapException e) {
      if (e.getCtapError() != CtapException.ERR_NO_CREDENTIALS) {
        throw e;
      }
    }

    return list;
  }

  /**
   * Enumerate credentials stored for a particular RP.
   *
   * @param rpIdHash The SHA-256 hash of an RP ID to enumerate for.
   * @return A list of Credentials.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   */
  public List<CredentialData> enumerateCredentials(byte[] rpIdHash)
      throws IOException, CommandException {
    List<CredentialData> list = new ArrayList<>();
    try {
      Map<Integer, ?> first =
          call(
              CMD_ENUMERATE_CREDS_BEGIN,
              Collections.singletonMap(PARAM_RP_ID_HASH, rpIdHash),
              true);
      list.add(CredentialData.fromData(first));
      int nCreds = Objects.requireNonNull((Integer) first.get(RESULT_TOTAL_CREDENTIALS));
      for (int i = nCreds; i > 1; i--) {
        list.add(CredentialData.fromData(call(CMD_ENUMERATE_CREDS_NEXT, null, false)));
      }
    } catch (CtapException e) {
      if (e.getCtapError() != CtapException.ERR_NO_CREDENTIALS) {
        throw e;
      }
    }
    return list;
  }

  /**
   * Delete a stored credential.
   *
   * @param credentialId A Map representing a PublicKeyCredentialDescriptor identifying a credential
   *     to delete.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   */
  public void deleteCredential(Map<String, ?> credentialId) throws IOException, CommandException {
    call(CMD_DELETE_CREDENTIAL, Collections.singletonMap(PARAM_CREDENTIAL_ID, credentialId), true);
  }

  /**
   * @return true if updating user information is supported
   */
  public boolean isUpdateUserInformationSupported() {
    return supportsCredMgmt(ctap.getCachedInfo());
  }

  /**
   * Update user information associated to a credential. Only supported on authenticators with
   * version FIDO_2_1 and greater.
   *
   * @param credentialId A Map representing a PublicKeyCredentialDescriptor identifying a credential
   *     to delete.
   * @param userEntity A Map representing a PublicKeyCredentialUserEntity containing the updated
   *     information.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @throws UnsupportedOperationException In case the functionality is not supported.
   */
  public void updateUserInformation(Map<String, ?> credentialId, Map<String, ?> userEntity)
      throws IOException, CommandException {

    if (!isUpdateUserInformationSupported()) {
      throw new UnsupportedOperationException("Update user information not supported");
    }

    Map<Integer, Object> parameters = new HashMap<>();
    parameters.put((int) PARAM_CREDENTIAL_ID, credentialId);
    parameters.put((int) PARAM_USER, userEntity);
    call(CMD_UPDATE_USER_INFORMATION, parameters, true);
  }

  /** CTAP2 Credential Management Metadata object. */
  public static class Metadata {
    private final int existingResidentCredentialsCount;
    private final int maxPossibleRemainingResidentCredentialsCount;

    private Metadata(
        int existingResidentCredentialsCount, int maxPossibleRemainingResidentCredentialsCount) {
      this.existingResidentCredentialsCount = existingResidentCredentialsCount;
      this.maxPossibleRemainingResidentCredentialsCount =
          maxPossibleRemainingResidentCredentialsCount;
    }

    /**
     * The total number of resident credentials existing on the authenticator.
     *
     * @return The number of existing resident credentials.
     */
    public int getExistingResidentCredentialsCount() {
      return existingResidentCredentialsCount;
    }

    /**
     * The maximum number of possible remaining credentials that can be created on the
     * authenticator. Note that this number is an estimate as actual space consumed to create a
     * credential depends on various conditions such as which algorithm is picked, user entity
     * information etc.
     *
     * @return The maximum number of possible remaining credentials that can be created.
     */
    public int getMaxPossibleRemainingResidentCredentialsCount() {
      return maxPossibleRemainingResidentCredentialsCount;
    }
  }

  /** A data class representing an RP for which one or more credentials may be stored. */
  public static class RpData {
    private final Map<String, ?> rp;
    private final byte[] rpIdHash;

    private RpData(Map<String, ?> rp, byte[] rpIdHash) {
      this.rp = rp;
      this.rpIdHash = rpIdHash;
    }

    public Map<String, ?> getRp() {
      return rp;
    }

    public byte[] getRpIdHash() {
      return rpIdHash;
    }

    @SuppressWarnings("unchecked")
    private static RpData fromData(Map<Integer, ?> data) {
      return new RpData(
          Objects.requireNonNull((Map<String, ?>) data.get(RESULT_RP)),
          Objects.requireNonNull((byte[]) data.get(RESULT_RP_ID_HASH)));
    }
  }

  /** A data class representing a stored credential. */
  public static class CredentialData {
    private final Map<String, ?> user;
    private final Map<String, ?> credentialId;
    private final Map<String, ?> publicKey;

    private CredentialData(
        Map<String, ?> user, Map<String, ?> credentialId, Map<String, ?> publicKey) {
      this.user = user;
      this.credentialId = credentialId;
      this.publicKey = publicKey;
    }

    public Map<String, ?> getUser() {
      return user;
    }

    public Map<String, ?> getCredentialId() {
      return credentialId;
    }

    public Map<String, ?> getPublicKey() {
      return publicKey;
    }

    @SuppressWarnings("unchecked")
    private static CredentialData fromData(Map<Integer, ?> data) {
      return new CredentialData(
          Objects.requireNonNull((Map<String, ?>) data.get(RESULT_USER)),
          Objects.requireNonNull((Map<String, ?>) data.get(RESULT_CREDENTIAL_ID)),
          Objects.requireNonNull((Map<String, ?>) data.get(RESULT_PUBLIC_KEY)));
    }
  }
}

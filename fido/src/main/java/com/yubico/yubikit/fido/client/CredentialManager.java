/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.fido.client;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Provides management of resident key type credentials, which are stored on a YubiKey.
 * An instance of this class can be obtained by calling {@link BasicWebAuthnClient#getCredentialManager(char[])}.
 */
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
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @throws ClientError      A higher level error.
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
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @throws ClientError      A higher level error.
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
     * @return A mapping between {@link PublicKeyCredentialDescriptor}s to their associated {@link PublicKeyCredentialUserEntity}
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @throws ClientError      A higher level error.
     */
    public Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> getCredentials(String rpId) throws IOException, CommandException, ClientError {
        try {
            Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> credentials = new HashMap<>();
            byte[] rpIdHash = rpIdHashes.get(rpId);
            if (rpIdHash == null) {
                rpIdHash = BasicWebAuthnClient.hash(rpId.getBytes(StandardCharsets.UTF_8));
            }
            for (CredentialManagement.CredentialData credData : credentialManagement.enumerateCredentials(rpIdHash)) {
                final Map<String, ?> user = credData.getUser();
                final Map<String, ?> credentialId = credData.getCredentialId();
                credentials.put(
                        new PublicKeyCredentialDescriptor(
                                PublicKeyCredentialType.fromString(Objects.requireNonNull((String) credentialId.get(PublicKeyCredentialDescriptor.TYPE))),
                                Objects.requireNonNull((byte[]) credentialId.get(PublicKeyCredentialDescriptor.ID))
                        ),
                        new PublicKeyCredentialUserEntity(
                                Objects.requireNonNull((String) user.get(PublicKeyCredentialUserEntity.NAME)),
                                Objects.requireNonNull((byte[]) user.get(PublicKeyCredentialUserEntity.ID)),
                                Objects.requireNonNull((String) user.get(PublicKeyCredentialUserEntity.DISPLAY_NAME)))
                );
            }
            return credentials;
        } catch (CtapException e) {
            throw ClientError.wrapCtapException(e);
        }
    }

    /**
     * Delete a stored credential from the YubiKey.
     *
     * @param credential A {@link PublicKeyCredentialDescriptor} which can be gotten from {@link #getCredentials(String)}.
     * @throws IOException      A communication error in the transport layer.
     * @throws CommandException A communication in the protocol layer.
     * @throws ClientError      A higher level error.
     */
    public void deleteCredential(PublicKeyCredentialDescriptor credential) throws IOException, CommandException, ClientError {
        try {

            final Map<String, Object> credentialMap = new HashMap<>();
            credentialMap.put(PublicKeyCredentialDescriptor.TYPE, credential.getType().toString());
            credentialMap.put(PublicKeyCredentialDescriptor.ID, credential.getId());

            credentialManagement.deleteCredential(credentialMap);
        } catch (CtapException e) {
            throw ClientError.wrapCtapException(e);
        }
    }
}

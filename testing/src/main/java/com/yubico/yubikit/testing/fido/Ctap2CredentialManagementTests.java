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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.SerializationType;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Ctap2CredentialManagementTests {
    /**
     * Deletes all resident keys. Assumes TestData.PIN is currently set as the PIN.
     */
    public static void deleteAllCredentials(CredentialManagement credentialManagement)
            throws IOException, CommandException {

        for (CredentialManagement.RpData rpData : credentialManagement.enumerateRps()) {
            for (CredentialManagement.CredentialData credData :
                    credentialManagement.enumerateCredentials(rpData.getRpIdHash())) {
                credentialManagement.deleteCredential(credData.getCredentialId());
            }
        }

        assertThat(credentialManagement.getMetadata().getExistingResidentCredentialsCount(), equalTo(0));
    }

    private static CredentialManagement setupCredentialManagement(
            Ctap2Session session, FidoTestState state
    ) throws IOException, CommandException {

        assumeTrue("Credential management not supported",
                CredentialManagement.isSupported(session.getCachedInfo()));

        ClientPin clientPin = new ClientPin(session, state.getPinUvAuthProtocol());

        return new CredentialManagement(
                session,
                clientPin.getPinUvAuth(),
                clientPin.getPinToken(TestData.PIN, ClientPin.PIN_PERMISSION_CM, null)
        );
    }

    public static void testReadMetadata(Ctap2Session session, FidoTestState state) throws Throwable {
        CredentialManagement credentialManagement = setupCredentialManagement(session, state);

        CredentialManagement.Metadata metadata = credentialManagement.getMetadata();

        assertThat(metadata.getExistingResidentCredentialsCount(), equalTo(0));
        assertThat(metadata.getMaxPossibleRemainingResidentCredentialsCount(), greaterThan(0));
    }

    public static void testManagement(Ctap2Session session, FidoTestState state) throws Throwable {

        CredentialManagement credentialManagement = setupCredentialManagement(session, state);

        final SerializationType cborType = SerializationType.CBOR;

        assertThat(credentialManagement.enumerateRps(), empty());

        Map<String, Object> options = new HashMap<>();
        options.put("rk", true);

        byte[] pinToken = new ClientPin(session, credentialManagement.getPinUvAuth())
                .getPinToken(TestData.PIN, ClientPin.PIN_PERMISSION_MC, TestData.RP.getId());
        byte[] pinAuth = credentialManagement.getPinUvAuth().authenticate(pinToken, TestData.CLIENT_DATA_HASH);
        session.makeCredential(
                TestData.CLIENT_DATA_HASH,
                TestData.RP.toMap(cborType),
                TestData.USER.toMap(cborType),
                Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256.toMap(cborType)),
                null,
                null,
                options,
                pinAuth,
                state.getPinUvAuthProtocol().getVersion(),
                null,
                null
        );


        // this sets correct permission for handling credential management commands
        credentialManagement = setupCredentialManagement(session, state);

        List<CredentialManagement.RpData> rps = credentialManagement.enumerateRps();
        assertThat(rps.size(), equalTo(1));
        CredentialManagement.RpData rpData = rps.get(0);
        assertThat(rpData.getRp().get("id"), equalTo(TestData.RP_ID));

        List<CredentialManagement.CredentialData> creds = credentialManagement.enumerateCredentials(rpData.getRpIdHash());
        assertThat(creds.size(), equalTo(1));
        CredentialManagement.CredentialData credData = creds.get(0);
        Map<String, ?> userData = credData.getUser();
        assertThat(userData.get("id"), equalTo(TestData.USER_ID));
        assertThat(userData.get("name"), equalTo(TestData.USER_NAME));
        assertThat(userData.get("displayName"), equalTo(TestData.USER_DISPLAY_NAME));

        deleteAllCredentials(credentialManagement);
    }
}

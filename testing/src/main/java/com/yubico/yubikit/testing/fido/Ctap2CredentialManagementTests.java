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

package com.yubico.yubikit.testing.fido;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.greaterThan;

public class Ctap2CredentialManagementTests {

    /**
     * Deletes all resident keys. Assumes TestData.PIN is currently set as the PIN.
     */
    public static void deleteAllCredentials(Ctap2Session session) throws IOException, CommandException {
        ClientPin clientPin = new ClientPin(session, new PinUvAuthProtocolV1());
        CredentialManagement credentialManagement = new CredentialManagement(
                session,
                clientPin.getPinUvAuth(),
                clientPin.getPinToken(TestData.PIN)
        );

        for (CredentialManagement.RpData rpData : credentialManagement.enumerateRps()) {
            for (CredentialManagement.CredentialData credData :
                    credentialManagement.enumerateCredentials(rpData.getRpIdHash())) {
                credentialManagement.deleteCredential(credData.getCredentialId());
            }
        }

        assertThat(credentialManagement.getMetadata().getExistingResidentCredentialsCount(), equalTo(0));
    }

    private static CredentialManagement setupCredentialManagement(
            Ctap2Session session
    ) throws IOException, CommandException {
        Ctap2ClientPinTests.ensureDefaultPinSet(session);
        ClientPin clientPin = new ClientPin(session, new PinUvAuthProtocolV1());
        return new CredentialManagement(
                session,
                clientPin.getPinUvAuth(),
                clientPin.getPinToken(TestData.PIN)
        );
    }

    public static void testReadMetadata(Ctap2Session session) throws Throwable {
        CredentialManagement credentialManagement = setupCredentialManagement(session);
        CredentialManagement.Metadata metadata = credentialManagement.getMetadata();

        assertThat(metadata.getExistingResidentCredentialsCount(), equalTo(0));
        assertThat(metadata.getMaxPossibleRemainingResidentCredentialsCount(), greaterThan(0));
    }

    public static void testManagement(Ctap2Session session) throws Throwable {
        CredentialManagement credentialManagement = setupCredentialManagement(session);

        assertThat(credentialManagement.enumerateRps(), empty());

        Map<String, Object> options = new HashMap<>();
        options.put("rk", true);

        byte[] pinToken = new ClientPin(session, credentialManagement.getPinUvAuth()).getPinToken(TestData.PIN);
        byte[] pinAuth = credentialManagement.getPinUvAuth().authenticate(pinToken, TestData.CLIENT_DATA_HASH);
        session.makeCredential(
                TestData.CLIENT_DATA_HASH,
                TestData.RP.toMap(),
                TestData.USER.toMap(),
                Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256.toMap()),
                null,
                null,
                options,
                pinAuth,
                1,
                null
        );

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
        assertThat(userData.get("displayName"), equalTo(TestData.USER_DISPLAYNAME));

        deleteAllCredentials(session);
    }
}

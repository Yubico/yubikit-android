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

import static com.yubico.yubikit.fido.client.BasicWebAuthnClient.OPTION_CREDENTIAL_MANAGEMENT;
import static com.yubico.yubikit.fido.client.BasicWebAuthnClient.OPTION_CREDENTIAL_MANAGEMENT_PREVIEW;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.fido.webauthn.SerializationType;

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
     * Asserts support of credential manager and returns if preview version of credential manager
     * should be used. If none of credential manager is supported, ends test.
     * @param session - the connected ctap2 session
     *
     * @return true if the session supports credentialManagerPreview, false if only
     * credentialManager is supported
     */
    private static boolean useCredentialMgmtPreview(Ctap2Session session)
            throws IOException, CommandException {
        final Ctap2Session.InfoData info = session.getInfo();

        final boolean credMgmt = supportsCredentialManager(info);
        final boolean credentialMgmtPreview = supportsCredentialManagerPreview(info);

        assertThat("No credential management support", credMgmt || credentialMgmtPreview);

        return credentialMgmtPreview && !credMgmt;
    }

    /**
     * Deletes all resident keys. Assumes TestData.PIN is currently set as the PIN.
     */
    public static void deleteAllCredentials(Ctap2Session session, boolean usePreview)
            throws IOException, CommandException {
        ClientPin clientPin = new ClientPin(session, new PinUvAuthProtocolV1());
        CredentialManagement credentialManagement = new CredentialManagement(
                session,
                clientPin.getPinUvAuth(),
                clientPin.getPinToken(TestData.PIN),
                usePreview
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
            Ctap2Session session,
            boolean usePreview
    ) throws IOException, CommandException {
        Ctap2ClientPinTests.ensureDefaultPinSet(session);
        ClientPin clientPin = new ClientPin(session, new PinUvAuthProtocolV1());
        return new CredentialManagement(
                session,
                clientPin.getPinUvAuth(),
                clientPin.getPinToken(TestData.PIN),
                usePreview
        );
    }

    private static boolean supportsCredentialManager(Ctap2Session.InfoData info) {
        return Boolean.TRUE.equals(info.getOptions().get(OPTION_CREDENTIAL_MANAGEMENT));
    }

    private static boolean supportsCredentialManagerPreview(Ctap2Session.InfoData info) {
        return Boolean.TRUE.equals(info.getOptions().get(OPTION_CREDENTIAL_MANAGEMENT_PREVIEW));
    }

    public static void testReadMetadata(Ctap2Session session) throws Throwable {
        final boolean usePreview = useCredentialMgmtPreview(session);
        CredentialManagement credentialManagement = setupCredentialManagement(session, usePreview);
        CredentialManagement.Metadata metadata = credentialManagement.getMetadata();

        assertThat(metadata.getExistingResidentCredentialsCount(), equalTo(0));
        assertThat(metadata.getMaxPossibleRemainingResidentCredentialsCount(), greaterThan(0));
    }

    public static void testManagement(Ctap2Session session) throws Throwable {
        final boolean usePreview = useCredentialMgmtPreview(session);

        CredentialManagement credentialManagement = setupCredentialManagement(session, usePreview);

        final SerializationType cborType = SerializationType.CBOR;

        assertThat(credentialManagement.enumerateRps(), empty());

        Map<String, Object> options = new HashMap<>();
        options.put("rk", true);

        byte[] pinToken = new ClientPin(session, credentialManagement.getPinUvAuth()).getPinToken(TestData.PIN);
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
                1,
                null,
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
        assertThat(userData.get("displayName"), equalTo(TestData.USER_DISPLAY_NAME));

        deleteAllCredentials(session, usePreview);
    }
}

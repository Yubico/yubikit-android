/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.testing.yubiotp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.yubiotp.YubiOtpSession;

public class YubiOtpDeviceTests {

    private static final char[] CHANGED_PASSWORD = "12341234".toCharArray();

    public static void testChangePassword(YubiOtpTestState state) throws Throwable {

        state.withYubiOtp(
                yubiOtp -> {
//                    assertTrue(yubiOtp.isAccessKeySet());
//                    assertTrue(yubiOtp.isLocked());
//                    assertFalse(yubiOtp.unlock(CHANGED_PASSWORD));
//                    assertTrue(yubiOtp.unlock(state.password));
//                    yubiOtp.setPassword(CHANGED_PASSWORD);
                });

        state.withYubiOtp(
                yubiOtp -> {
//                    assertTrue(yubiOtp.isAccessKeySet());
//                    assertTrue(yubiOtp.isLocked());
//                    assertTrue(yubiOtp.unlock(CHANGED_PASSWORD));
                });
    }

    public static void testRemovePassword(YubiOtpSession yubiOtp, YubiOtpTestState state) throws Exception {
//        assertTrue(yubiOtp.isAccessKeySet());
//        assertTrue(yubiOtp.isLocked());
//        assertTrue(yubiOtp.unlock(state.password));

        if (state.isFipsApproved) {
            // trying remove password from a FIPS approved key throws specific ApduException
//            ApduException apduException = assertThrows(ApduException.class, yubiOtp::deleteAccessKey);
//            assertEquals(SW.CONDITIONS_NOT_SATISFIED, apduException.getSw());
//            // the key is still password protected
//            assertTrue(yubiOtp.isAccessKeySet());
        } else {
//            yubiOtp.deleteAccessKey();
//            assertFalse(yubiOtp.isAccessKeySet());
//            assertFalse(yubiOtp.isLocked());
        }
    }

    public static void testAccountManagement(YubiOtpSession yubiOtp, YubiOtpTestState state) throws Exception {
//        assertTrue(yubiOtp.unlock(state.password));
//        List<Credential> credentials = yubiOtp.getCredentials();
//        assertEquals(0, credentials.size());
//        final String uri = "otpauth://totp/foobar:bob@example.com?secret=abba";
//        CredentialData credentialData = CredentialData.parseUri(new URI(uri));
//        yubiOtp.putCredential(credentialData, false);
//
//        credentials = yubiOtp.getCredentials();
//        assertEquals(1, credentials.size());
//        Credential credential = credentials.get(0);
//        assertEquals("bob@example.com", credential.getAccountName());
//        assertEquals("foobar", credential.getIssuer());
//
//        yubiOtp.deleteCredential(credential.getId());
//        credentials = yubiOtp.getCredentials();
//        assertEquals(0, credentials.size());
    }

    public static void testRenameAccount(YubiOtpSession yubiOtp, YubiOtpTestState state) throws Exception {
//        Assume.assumeTrue(yubiOtp.supports(FEATURE_RENAME));
//        assertTrue(yubiOtp.unlock(state.password));
//        List<Credential> credentials = yubiOtp.getCredentials();
//        assertEquals(0, credentials.size());
//        final String uri = "otpauth://totp/foobar:bob@example.com?secret=abba";
//        CredentialData credentialData = CredentialData.parseUri(new URI(uri));
//        yubiOtp.putCredential(credentialData, false);
//
//        credentials = yubiOtp.getCredentials();
//        assertEquals(1, credentials.size());
//
//        Credential credential = credentials.get(0);
//        credential = yubiOtp.renameCredential(credential, "ann@example.com", null);
//        assertEquals("ann@example.com", credential.getAccountName());
//        assertNull(credential.getIssuer());
//
//        credentials = yubiOtp.getCredentials();
//        assertEquals(1, credentials.size());
//        credential = credentials.get(0);
//        assertEquals("ann@example.com", credential.getAccountName());
//        assertNull(credential.getIssuer());
//
//        yubiOtp.deleteCredential(credential.getId());
//        credentials = yubiOtp.getCredentials();
//        assertEquals(0, credentials.size());
    }
}

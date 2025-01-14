/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.testing.oath;

import static com.yubico.yubikit.oath.OathSession.FEATURE_RENAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.oath.Credential;
import com.yubico.yubikit.oath.CredentialData;
import com.yubico.yubikit.oath.OathSession;
import java.net.URI;
import java.util.List;
import org.junit.Assume;

public class OathDeviceTests {

  private static final char[] CHANGED_PASSWORD = "12341234".toCharArray();

  public static void testChangePassword(OathTestState state) throws Throwable {

    state.withOath(
        oath -> {
          assertTrue(oath.isAccessKeySet());
          assertTrue(oath.isLocked());
          assertFalse(oath.unlock(CHANGED_PASSWORD));
          assertTrue(oath.unlock(state.password));
          oath.setPassword(CHANGED_PASSWORD);
        });

    state.withOath(
        oath -> {
          assertTrue(oath.isAccessKeySet());
          assertTrue(oath.isLocked());
          assertTrue(oath.unlock(CHANGED_PASSWORD));
        });
  }

  public static void testRemovePassword(OathSession oath, OathTestState state) throws Exception {
    assertTrue(oath.isAccessKeySet());
    assertTrue(oath.isLocked());
    assertTrue(oath.unlock(state.password));

    if (state.isFipsApproved) {
      // trying remove password from a FIPS approved key throws specific ApduException
      ApduException apduException = assertThrows(ApduException.class, oath::deleteAccessKey);
      assertEquals(SW.CONDITIONS_NOT_SATISFIED, apduException.getSw());
      // the key is still password protected
      assertTrue(oath.isAccessKeySet());
    } else {
      oath.deleteAccessKey();
      assertFalse(oath.isAccessKeySet());
      assertFalse(oath.isLocked());
    }
  }

  public static void testAccountManagement(OathSession oath, OathTestState state) throws Exception {
    assertTrue(oath.unlock(state.password));
    List<Credential> credentials = oath.getCredentials();
    assertEquals(0, credentials.size());
    final String uri = "otpauth://totp/foobar:bob@example.com?secret=abba";
    CredentialData credentialData = CredentialData.parseUri(new URI(uri));
    oath.putCredential(credentialData, false);

    credentials = oath.getCredentials();
    assertEquals(1, credentials.size());
    Credential credential = credentials.get(0);
    assertEquals("bob@example.com", credential.getAccountName());
    assertEquals("foobar", credential.getIssuer());

    oath.deleteCredential(credential.getId());
    credentials = oath.getCredentials();
    assertEquals(0, credentials.size());
  }

  public static void testRenameAccount(OathSession oath, OathTestState state) throws Exception {
    Assume.assumeTrue(oath.supports(FEATURE_RENAME));
    assertTrue(oath.unlock(state.password));
    List<Credential> credentials = oath.getCredentials();
    assertEquals(0, credentials.size());
    final String uri = "otpauth://totp/foobar:bob@example.com?secret=abba";
    CredentialData credentialData = CredentialData.parseUri(new URI(uri));
    oath.putCredential(credentialData, false);

    credentials = oath.getCredentials();
    assertEquals(1, credentials.size());

    Credential credential = credentials.get(0);
    credential = oath.renameCredential(credential, "ann@example.com", null);
    assertEquals("ann@example.com", credential.getAccountName());
    assertNull(credential.getIssuer());

    credentials = oath.getCredentials();
    assertEquals(1, credentials.size());
    credential = credentials.get(0);
    assertEquals("ann@example.com", credential.getAccountName());
    assertNull(credential.getIssuer());

    oath.deleteCredential(credential.getId());
    credentials = oath.getCredentials();
    assertEquals(0, credentials.size());
  }
}

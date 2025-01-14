/*
 * Copyright (C) 2020-2022 Yubico.
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

package com.yubico.yubikit.oath;

import java.nio.charset.StandardCharsets;
import org.junit.Assert;
import org.junit.Test;

public class CredentialIdUtilsTest {
  @Test
  public void testParseData() {
    final String issuer = "issuer";
    String accountId = "20/issuer:account";
    CredentialIdUtils.CredentialIdData idData =
        CredentialIdUtils.parseId(accountId.getBytes(StandardCharsets.UTF_8), OathType.TOTP);
    Assert.assertEquals(issuer, idData.issuer);
    Assert.assertEquals(20, idData.period);
    byte[] credentialId =
        CredentialIdUtils.formatId(idData.issuer, idData.accountName, OathType.TOTP, idData.period);
    Assert.assertEquals(accountId, new String(credentialId, StandardCharsets.UTF_8));

    String accountWithSlash = "this/account";
    idData =
        CredentialIdUtils.parseId(accountWithSlash.getBytes(StandardCharsets.UTF_8), OathType.TOTP);
    Assert.assertNull(idData.issuer);
    Assert.assertEquals(accountWithSlash, idData.accountName);
    credentialId =
        CredentialIdUtils.formatId(idData.issuer, idData.accountName, OathType.TOTP, idData.period);
    Assert.assertEquals(accountWithSlash, new String(credentialId, StandardCharsets.UTF_8));

    String accountWithSlashAndIssuer = "issuer:this/account";
    idData =
        CredentialIdUtils.parseId(
            accountWithSlashAndIssuer.getBytes(StandardCharsets.UTF_8), OathType.TOTP);
    Assert.assertEquals(issuer, idData.issuer);
    Assert.assertEquals(accountWithSlash, idData.accountName);
    credentialId =
        CredentialIdUtils.formatId(idData.issuer, idData.accountName, OathType.TOTP, idData.period);
    Assert.assertEquals(
        accountWithSlashAndIssuer, new String(credentialId, StandardCharsets.UTF_8));

    String issuerAndAccountWithSlash = "this/issuer:this/account";
    idData =
        CredentialIdUtils.parseId(
            issuerAndAccountWithSlash.getBytes(StandardCharsets.UTF_8), OathType.TOTP);
    Assert.assertEquals("this/issuer", idData.issuer);
    Assert.assertEquals(accountWithSlash, idData.accountName);
    credentialId =
        CredentialIdUtils.formatId(idData.issuer, idData.accountName, OathType.TOTP, idData.period);
    Assert.assertEquals(
        issuerAndAccountWithSlash, new String(credentialId, StandardCharsets.UTF_8));

    String accountWithSlashAndColon = "issuer:this:account";
    idData =
        CredentialIdUtils.parseId(
            accountWithSlashAndColon.getBytes(StandardCharsets.UTF_8), OathType.TOTP);
    Assert.assertEquals(issuer, idData.issuer);
    Assert.assertEquals("this:account", idData.accountName);
    credentialId =
        CredentialIdUtils.formatId(idData.issuer, idData.accountName, OathType.TOTP, idData.period);
    Assert.assertEquals(accountWithSlashAndColon, new String(credentialId, StandardCharsets.UTF_8));

    String hotpWithPeriod = "20/HOTP:example";
    idData =
        CredentialIdUtils.parseId(hotpWithPeriod.getBytes(StandardCharsets.UTF_8), OathType.HOTP);
    Assert.assertEquals("20/HOTP", idData.issuer);
    Assert.assertEquals("example", idData.accountName);
    credentialId =
        CredentialIdUtils.formatId(idData.issuer, idData.accountName, OathType.HOTP, idData.period);
    Assert.assertEquals(hotpWithPeriod, new String(credentialId, StandardCharsets.UTF_8));
  }
}

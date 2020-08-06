/*
 * Copyright (C) 2019 Yubico.
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

import org.junit.Assert;
import org.junit.Test;

import java.net.URI;
import java.net.URISyntaxException;

public class CredentialDataTest {

    @Test
    public void testParseUriGood() throws ParseUriException, URISyntaxException {
        Assert.assertArrayEquals(
                new byte[]{0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, (byte) 0xde, (byte) 0xad, (byte) 0xbe, (byte) 0xef},
                CredentialData.parseUri(new URI("otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")).getSecret()
        );
        Assert.assertArrayEquals(
                new byte[]{0x0a, (byte) 0xc0, 0x77, 0x34, (byte) 0xc0},
                CredentialData.parseUri(new URI("otpauth://hotp/foobar:bob@example.com?secret=blahonga")).getSecret()
        );
        Assert.assertArrayEquals(
                new byte[]{0x00, 0x42},
                CredentialData.parseUri(new URI("otpauth://totp/foobar:bob@example.com?secret=abba")).getSecret()
        );
    }

    @Test
    public void testParseIssuer() throws ParseUriException, URISyntaxException {
        CredentialData noIssuer = CredentialData.parseUri(new URI("otpauth://totp/account?secret=abba"));
        Assert.assertNull(noIssuer.getIssuer());
        CredentialData usingParam = CredentialData.parseUri(new URI("otpauth://totp/account?secret=abba&issuer=Issuer"));
        Assert.assertEquals(usingParam.getIssuer(), "Issuer");
        CredentialData usingSeparator = CredentialData.parseUri(new URI("otpauth://totp/Issuer:account?secret=abba"));
        Assert.assertEquals(usingSeparator.getIssuer(), "Issuer");
        CredentialData usingBoth = CredentialData.parseUri(new URI("otpauth://totp/IssuerA:account?secret=abba&issuer=IssuerB"));
        Assert.assertEquals(usingBoth.getIssuer(), "IssuerA");
    }

    @Test(expected = ParseUriException.class)
    public void testParseHttpUri() throws ParseUriException, URISyntaxException {
        CredentialData.parseUri(new URI("http://example.com/"));
    }

    @Test(expected = ParseUriException.class)
    public void testParseWrongPath() throws ParseUriException, URISyntaxException {
        CredentialData.parseUri(new URI("otpauth://foobar?secret=kaka"));
    }

    @Test(expected = ParseUriException.class)
    public void testParseNonUri() throws ParseUriException, URISyntaxException {
        CredentialData.parseUri(new URI("foobar"));
    }

    @Test(expected = ParseUriException.class)
    public void testParseSecretNotBase32() throws ParseUriException, URISyntaxException {
        CredentialData.parseUri(new URI("otpauth://totp/Example:alice@google.com?secret=balhonga1&issuer=Example"));
    }

    @Test(expected = ParseUriException.class)
    public void testParseMissingAlgorithm() throws ParseUriException, URISyntaxException {
        CredentialData.parseUri(new URI("otpauth:///foo:mallory@example.com?secret=kaka"));
    }
}

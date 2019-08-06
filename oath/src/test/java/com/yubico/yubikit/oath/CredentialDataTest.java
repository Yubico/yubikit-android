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

import android.net.Uri;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class CredentialDataTest {

    @Test
    public void testParseUriGood() throws ParseUriException {
        String[] goodUris = new String[] {
                "otpauth://totp/Example:alice@google.com?secret=JBSWY3DPEHPK3PXP&issuer=Example",
                "otpauth://hotp/foobar:bob@example.com?secret=blahonga2",
                "otpauth://hotp/foobar:bob@example.com?secret=ab16f9",
                "otpauth://totp/foobar:bob@example.com?secret=secret"
        };
        for (String uri : goodUris) {
            Credential.parseUri(Uri.parse(uri));
        }
    }

    @Test
    public void testParseIssuer() throws ParseUriException {
        Credential noIssuer = Credential.parseUri(Uri.parse("otpauth://totp/account?secret=abba"));
        Assert.assertNull(noIssuer.getIssuer());
        Credential usingParam = Credential.parseUri(Uri.parse("otpauth://totp/account?secret=abba&issuer=Issuer"));
        Assert.assertEquals(usingParam.getIssuer(), "Issuer");
        Credential usingSeparator = Credential.parseUri(Uri.parse("otpauth://totp/Issuer:account?secret=abba"));
        Assert.assertEquals(usingSeparator.getIssuer(), "Issuer");
        Credential usingBoth = Credential.parseUri(Uri.parse("otpauth://totp/IssuerA:account?secret=abba&issuer=IssuerB"));
        Assert.assertEquals(usingBoth.getIssuer(), "IssuerA");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testParseNull() throws ParseUriException {
        Credential.parseUri(null);
    }

    @Test(expected = ParseUriException.class)
    public void testParseHttpUri() throws ParseUriException {
        Credential.parseUri(Uri.parse("http://example.com/"));
    }

    @Test(expected = ParseUriException.class)
    public void testParseWrongPath() throws ParseUriException {
        Credential.parseUri(Uri.parse("otpauth://foobar?secret=kaka"));
    }

    @Test(expected = ParseUriException.class)
    public void testParseNonUri() throws ParseUriException {
        Credential.parseUri(Uri.parse("foobar"));
    }

    @Test(expected = ParseUriException.class)
    public void testParseSecretNotBase32() throws ParseUriException {
        Credential.parseUri(Uri.parse("otpauth://totp/Example:alice@google.com?secret=balhonga1&issuer=Example"));
    }

    @Test(expected = ParseUriException.class)
    public void testParseMissingAlgorithm() throws ParseUriException {
        Credential.parseUri(Uri.parse("otpauth:///foo:mallory@example.com?secret=kaka"));
    }
}

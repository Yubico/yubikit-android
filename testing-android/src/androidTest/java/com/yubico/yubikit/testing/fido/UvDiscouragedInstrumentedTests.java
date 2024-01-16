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

package com.yubico.yubikit.testing.fido;

import androidx.test.filters.LargeTest;

import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;

import org.junit.Test;

@LargeTest
public class UvDiscouragedInstrumentedTests extends FidoInstrumentedTests {

    static boolean hasPin(Ctap2Session session) {
        final Ctap2Session.InfoData info = session.getCachedInfo();
        return Boolean.TRUE.equals(info.getOptions().get("clientPin"));
    }

    @Test
    public void testMakeCredentialGetAssertion() throws Throwable {
        withCtap2Session(
                "This device has a PIN set",
                (device, session) -> !hasPin(session),
                BasicWebAuthnClientTests::testUvDiscouragedMakeCredentialGetAssertion);
    }


    /**
     * Run this test only on devices with PIN set
     * this is expected to fail with 0x36
     */
    @Test(expected = ClientError.class)
    public void testMakeCredentialGetAssertionOnProtected() throws Throwable {
        withCtap2Session(
                "This device has no PIN set",
                (device, session) -> hasPin(session),
                BasicWebAuthnClientTests::testUvDiscouragedMakeCredentialGetAssertion);
    }
}

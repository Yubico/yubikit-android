/*
 * Copyright (C) 2023 Yubico.
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

import static com.yubico.yubikit.testing.fido.Ctap2ClientPinInstrumentedTests.supportsPinUvAuthProtocol;

import androidx.test.filters.LargeTest;

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

@RunWith(Enclosed.class)
public class EnterpriseAttestationInstrumentedTests {
    @LargeTest
    @RunWith(Parameterized.class)
    public static class EnterpriseAttestationParametrizedTests extends FidoInstrumentedTests {

        @Parameterized.Parameter
        public PinUvAuthProtocol pinUvAuthProtocol;

        @Parameterized.Parameters
        public static Collection<PinUvAuthProtocol> data() {
            return Arrays.asList(
                    new PinUvAuthProtocolV1(),
                    new PinUvAuthProtocolV2());
        }

        static boolean isEnterpriseAttestationsSupported(Ctap2Session session) {
            final Ctap2Session.InfoData info = session.getCachedInfo();
            return info.getOptions().containsKey("ep");
        }

        static boolean isSupported(Ctap2Session session,
                                   PinUvAuthProtocol pinUvAuthProtocol) {
            return isEnterpriseAttestationsSupported(session) &&
                    supportsPinUvAuthProtocol(session, pinUvAuthProtocol);
        }

        @Test
        public void testSupportedPlatformManagedEA() throws Throwable {
            withCtap2Session(
                    "Enterprise attestation is not supported/enabled",
                    (device, session) -> isSupported(session, pinUvAuthProtocol),
                    EnterpriseAttestationTests::testSupportedPlatformManagedEA,
                    pinUvAuthProtocol);
        }

        @Test
        public void testUnsupportedPlatformManagedEA() throws Throwable {
            withCtap2Session(
                    "Enterprise attestation is not supported/enabled",
                    (device, session) -> isSupported(session, pinUvAuthProtocol),
                    EnterpriseAttestationTests::testUnsupportedPlatformManagedEA,
                    pinUvAuthProtocol);
        }

        @Test
        public void testCreateOptionsAttestationPreference() throws Throwable {
            withCtap2Session(
                    "Enterprise attestation is not supported/enabled",
                    (device, session) -> isSupported(session, pinUvAuthProtocol),
                    EnterpriseAttestationTests::testCreateOptionsAttestationPreference,
                    pinUvAuthProtocol);
        }

        @Test
        public void testVendorFacilitatedEA() throws Throwable {
            withCtap2Session(
                    "Enterprise attestation is not supported/enabled",
                    (device, session) -> isSupported(session, pinUvAuthProtocol),
                    EnterpriseAttestationTests::testVendorFacilitatedEA,
                    pinUvAuthProtocol);
        }
    }
}

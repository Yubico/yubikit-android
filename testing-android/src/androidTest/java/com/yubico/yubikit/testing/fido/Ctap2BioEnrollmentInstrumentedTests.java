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

import com.yubico.yubikit.fido.ctap.BioEnrollment;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;

import org.junit.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;

@LargeTest
public class Ctap2BioEnrollmentInstrumentedTests extends FidoInstrumentedTests {

    @Test
    public void testFingerprintEnrollment() {
        runTest(Ctap2BioEnrollmentTests::testFingerprintEnrollment);
    }

    // helpers
    private final static Logger logger =
            LoggerFactory.getLogger(Ctap2BioEnrollmentInstrumentedTests.class);

    private static boolean supportsPinUvAuthProtocol(
            Ctap2Session session,
            int pinUvAuthProtocolVersion) {
        final List<Integer> pinUvAuthProtocols =
                session.getCachedInfo().getPinUvAuthProtocols();
        return pinUvAuthProtocols.contains(pinUvAuthProtocolVersion);
    }

    private static boolean supportsBioEnrollment(Ctap2Session session) {
        return BioEnrollment.isSupported(session.getCachedInfo());
    }

    private static boolean isSupported(Ctap2Session session) {
        return supportsBioEnrollment(session) && supportsPinUvAuthProtocol(session, 2);
    }

    private void runTest(Callback callback) {
        try {
            withCtap2Session(
                    "Bio enrollment or pinUvProtocol Two not supported",
                    (device, session) -> supportsBioEnrollment(session) && supportsPinUvAuthProtocol(session, 2),
                    callback,
                    new PinUvAuthProtocolV2()
            );
        } catch (Throwable throwable) {
            logger.error("Caught exception: ", throwable);
        }
    }
}

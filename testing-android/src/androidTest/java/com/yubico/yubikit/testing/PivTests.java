/*
 * Copyright (C) 2022 Yubico.
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

package com.yubico.yubikit.testing;

import com.yubico.yubikit.testing.framework.PivInstrumentedTests;
import com.yubico.yubikit.testing.piv.PivCertificateTests;
import com.yubico.yubikit.testing.piv.PivDeviceTests;

import org.junit.Test;

public class PivTests extends PivInstrumentedTests {

    @Test
    public void testPin() throws Throwable {
        withPivSession(PivDeviceTests::testPin);
    }

    @Test
    public void testPuk() throws Throwable {
        withPivSession(PivDeviceTests::testPuk);
    }

    @Test
    public void testManagementKey() throws Throwable {
        withPivSession(PivDeviceTests::testManagementKey);
    }

    @Test
    public void testPutUncompressedCertificate() throws Throwable {
        withPivSession(PivCertificateTests::putUncompressedCertificate);
    }

    @Test
    public void testPutCompressedCertificate() throws Throwable {
        withPivSession(PivCertificateTests::putCompressedCertificate);
    }
}

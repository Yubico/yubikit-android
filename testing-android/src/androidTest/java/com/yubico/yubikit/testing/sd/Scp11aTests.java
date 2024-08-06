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

package com.yubico.yubikit.testing.sd;

import com.yubico.yubikit.testing.framework.SecurityDomainInstrumentedTests;

import org.junit.Before;
import org.junit.Test;

public class Scp11aTests extends SecurityDomainInstrumentedTests {

    @Before
    public void before() throws Throwable {
        withState(Scp11aDeviceTests::before);
    }

    @Test
    public void testImportKey() throws Throwable {
        withState(Scp11aDeviceTests::testImportKey);
        withState(Scp11aDeviceTests::testImportKeyAlt);
    }

    @Test
    public void testAuthenticate() throws Throwable {
        withState(Scp11aDeviceTests::testAuthenticate);
    }

    @Test
    public void testAllowlist() throws Throwable {
        withState(Scp11aDeviceTests::testAllowList);
    }

    @Test
    public void testAllowlistBlocked() throws Throwable {
        withState(Scp11aDeviceTests::testAllowListBlocked);
    }

    @Test
    public void testScp11cAuthenticate() throws Throwable {
        withState(Scp11aDeviceTests::testScp11cAuthenticate);
    }

    @Test
    public void testScp11bAuthenticate() throws Throwable {
        withState(Scp11aDeviceTests::testScp11bAuthenticate);
    }

    @Test
    public void testScp11bWrongPubKey() throws Throwable {
        withState(Scp11aDeviceTests::testScp11bWrongPubKey);
    }

    @Test
    public void testScp11bImport() throws Throwable {
        withState(Scp11aDeviceTests::testScp11bImport);
    }
}

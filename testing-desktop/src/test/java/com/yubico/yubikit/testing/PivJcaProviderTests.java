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
import com.yubico.yubikit.testing.piv.PivJcaDecryptTests;
import com.yubico.yubikit.testing.piv.PivJcaDeviceTests;
import com.yubico.yubikit.testing.piv.PivJcaSigningTests;

import org.junit.Test;
import org.junit.runner.RunWith;

public class PivJcaProviderTests extends PivInstrumentedTests {

    @Test
    public void testGenerateKeys() throws Throwable {
        withPivSession(PivJcaDeviceTests::testGenerateKeys);
    }

    @Test
    public void testImportKeys() throws Throwable {
        withPivSession(PivJcaDeviceTests::testImportKeys);
    }

    @Test
    public void testSigning() throws Throwable {
        withPivSession(PivJcaSigningTests::testSign);
    }

    @Test
    public void testDecrypt() throws Throwable {
        withPivSession(PivJcaDecryptTests::testDecrypt);
    }
}

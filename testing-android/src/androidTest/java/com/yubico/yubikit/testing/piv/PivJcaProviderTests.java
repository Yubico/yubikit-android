/*
 * Copyright (C) 2022-2024 Yubico.
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

package com.yubico.yubikit.testing.piv;

import androidx.test.ext.junit.runners.AndroidJUnit4;

import com.yubico.yubikit.testing.framework.PivInstrumentedTests;

import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class PivJcaProviderTests extends PivInstrumentedTests {

    @Test
    public void testGenerateKeys() throws Throwable {
        withPivSession(PivJcaDeviceTests::testGenerateKeys);
    }

    @Test
    public void testGenerateKeysPreferBC() throws Throwable {
        withPivSession(PivJcaDeviceTests::testGenerateKeysPreferBC);
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

    @Test
    public void testMoveKey() throws Throwable {
        withPivSession(PivMoveKeyTests::moveKey);
    }
}

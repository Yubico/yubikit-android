/*
 * Copyright (C) 2022-2023 Yubico.
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

import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;

import org.junit.Test;

@LargeTest
public class Ctap2CredentialManagementInstrumentedTests extends FidoInstrumentedTests {
    @Test
    public void testReadMetadata() throws Throwable {
        withCtap2Session(Ctap2CredentialManagementTests::testReadMetadata);
    }

    @Test
    public void testManagement() throws Throwable {
        withCtap2Session(Ctap2CredentialManagementTests::testManagement);
    }
}

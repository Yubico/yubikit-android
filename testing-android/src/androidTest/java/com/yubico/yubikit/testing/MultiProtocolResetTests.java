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

package com.yubico.yubikit.testing;

import com.yubico.yubikit.testing.framework.DeviceInstrumentedTests;

import org.junit.Before;
import org.junit.Test;

public class MultiProtocolResetTests extends DeviceInstrumentedTests {

    @Before
    public void setupDevice() throws Throwable {
        withDevice(MultiProtocolResetDeviceTests::setupDevice);
    }

    @Test
    public void testSettingPivPinBlocksFidoReset() throws Throwable {
        withDevice(MultiProtocolResetDeviceTests::testSettingPivPinBlocksFidoReset);
    }

    @Test
    public void testPivOperationBlocksFidoReset() throws Throwable {
        withDevice(MultiProtocolResetDeviceTests::testPivOperationBlocksFidoReset);
    }

    @Test
    public void testSettingFidoPinBlocksPivReset() throws Throwable {
        withDevice(MultiProtocolResetDeviceTests::testSettingFidoPinBlocksPivReset);
    }
}

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

package com.yubico.yubikit.testing.framework;

import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.oath.OathSession;
import com.yubico.yubikit.testing.TestState;
import com.yubico.yubikit.testing.oath.OathTestUtils;

import org.junit.Before;

public class OathInstrumentedTests extends YKInstrumentedTests {

    public interface Callback {
        void invoke(OathSession value) throws Throwable;
    }

    private boolean shouldVerifyAndSetupSession = true;

    @Before
    public void initializeDeviceTest() {
        shouldVerifyAndSetupSession = true;
    }

    /** This method can be called several times during one test.
     * <p>
     * It will reset and setup the OATH session only the first time it is called.
     * The subsequent calls will not reset the device. This simulates YubiKey disconnecting/connecting.
     */
    protected void withOathSession(Callback callback) throws Throwable {
        if (shouldVerifyAndSetupSession) {
            OathTestUtils.verifyAndSetup(device, getScpKid());
            shouldVerifyAndSetupSession = false;
        } else {
            OathTestUtils.updateFipsApprovedValue(device);
        }

        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            callback.invoke(new OathSession(connection, TestState.keyParams));
        }
    }
}
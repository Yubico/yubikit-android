/*
 * Copyright (C) 2022,2024 Yubico.
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
import com.yubico.yubikit.openpgp.OpenPgpSession;
import com.yubico.yubikit.testing.openpgp.OpenPgpTestUtils;

public class OpenPgpInstrumentedTests extends YKInstrumentedTests {

    public interface Callback {
        void invoke(OpenPgpSession value) throws Throwable;
    }

    protected void withOpenPgpSession(Callback callback) throws Throwable {

        OpenPgpTestUtils.verifyAndSetup(device, scpParameters);

        try (SmartCardConnection connection = device.openConnection(SmartCardConnection.class)) {
            callback.invoke(new OpenPgpSession(connection, scpParameters.getKeyParams()));
        }
    }
}
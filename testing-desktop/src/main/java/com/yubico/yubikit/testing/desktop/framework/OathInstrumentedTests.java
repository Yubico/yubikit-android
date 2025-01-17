/*
 * Copyright (C) 2024-2025 Yubico.
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
package com.yubico.yubikit.testing.desktop.framework;

import com.yubico.yubikit.oath.OathSession;
import com.yubico.yubikit.testing.TestState;
import com.yubico.yubikit.testing.oath.OathTestState;

public class OathInstrumentedTests extends YKInstrumentedTests {

  protected void withDevice(TestState.StatefulDeviceCallback<OathTestState> callback)
      throws Throwable {
    final OathTestState state =
        new OathTestState.Builder(device, usbPid)
            .scpKid(getScpKid())
            .reconnectDeviceCallback(this::reconnectDevice)
            .build();

    state.withDeviceCallback(callback);
  }

  protected void withOathSession(
      TestState.StatefulSessionCallback<OathSession, OathTestState> callback) throws Throwable {
    final OathTestState state =
        new OathTestState.Builder(device, usbPid).scpKid(getScpKid()).build();
    state.withOath(callback);
  }
}

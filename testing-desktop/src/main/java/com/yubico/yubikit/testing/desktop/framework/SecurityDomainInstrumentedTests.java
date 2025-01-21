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

import com.yubico.yubikit.testing.TestState;
import com.yubico.yubikit.testing.sd.SecurityDomainTestState;

public class SecurityDomainInstrumentedTests extends YKInstrumentedTests {

  protected void withState(TestState.StatefulDeviceCallback<SecurityDomainTestState> callback)
      throws Throwable {
    final SecurityDomainTestState state =
        new SecurityDomainTestState.Builder(device, usbPid)
            .reconnectDeviceCallback(this::reconnectDevice)
            .build();

    state.withDeviceCallback(callback);
  }
}

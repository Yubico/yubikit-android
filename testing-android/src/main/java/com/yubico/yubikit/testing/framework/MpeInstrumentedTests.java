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

package com.yubico.yubikit.testing.framework;

import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.testing.TestState;
import com.yubico.yubikit.testing.mpe.MpeTestState;

public class MpeInstrumentedTests extends YKInstrumentedTests {

  protected void withPivSession(
      TestState.StatefulSessionCallback<PivSession, MpeTestState> callback) throws Throwable {
    final MpeTestState state = new MpeTestState.Builder(device, usbPid).scpKid(getScpKid()).build();
    state.withPiv(callback);
  }

  protected void withCtap2Session(
      TestState.StatefulSessionCallback<Ctap2Session, MpeTestState> callback) throws Throwable {
    final MpeTestState state = new MpeTestState.Builder(device, usbPid).scpKid(getScpKid()).build();
    state.withCtap2(callback);
  }
}

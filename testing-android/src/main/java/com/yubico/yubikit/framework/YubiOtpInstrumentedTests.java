/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit.framework;

import com.yubico.yubikit.TestState;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.yubiotp.YubiOtpSession;
import com.yubico.yubikit.yubiotp.YubiOtpTestState;
import java.util.Arrays;
import java.util.List;

public class YubiOtpInstrumentedTests extends YkInstrumentedTests {

  public static List<Class<? extends YubiKeyConnection>> connectionTypes =
      Arrays.asList(OtpConnection.class, SmartCardConnection.class);

  protected void withYubiOtpSession(
      TestState.StatefulSessionCallback<YubiOtpSession, YubiOtpTestState> callback)
      throws Throwable {
    final YubiOtpTestState state =
        new YubiOtpTestState.Builder(device, connectionTypes, usbPid).scpKid(getScpKid()).build();
    state.withYubiOtp(callback);
  }
}

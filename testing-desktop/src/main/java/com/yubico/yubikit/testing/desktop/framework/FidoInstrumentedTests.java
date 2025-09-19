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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.testing.TestState;
import com.yubico.yubikit.testing.fido.FidoTestState;
import java.util.Arrays;
import java.util.List;
import org.jetbrains.annotations.Nullable;

public class FidoInstrumentedTests extends YKInstrumentedTests {

  public static List<Class<? extends YubiKeyConnection>> connectionTypes =
      Arrays.asList(FidoConnection.class, SmartCardConnection.class);

  protected void withDevice(TestState.StatefulDeviceCallback<FidoTestState> callback)
      throws Throwable {
    FidoTestState state =
        new FidoTestState.Builder(device, connectionTypes, usbPid, getPinUvAuthProtocol())
            .scpKid(getScpKid())
            .reconnectDeviceCallback(this::reconnectDevice)
            .setPin(true)
            .build();

    state.withDeviceCallback(callback);
  }

  protected void withDevice(
      boolean setPin, TestState.StatefulDeviceCallback<FidoTestState> callback) throws Throwable {
    FidoTestState state =
        new FidoTestState.Builder(device, connectionTypes, usbPid, getPinUvAuthProtocol())
            .scpKid(getScpKid())
            .reconnectDeviceCallback(this::reconnectDevice)
            .setPin(setPin)
            .build();

    state.withDeviceCallback(callback);
  }

  protected void withCtap2Session(
      TestState.StatefulSessionCallback<Ctap2Session, FidoTestState> callback) throws Throwable {
    FidoTestState state =
        new FidoTestState.Builder(device, connectionTypes, usbPid, getPinUvAuthProtocol())
            .scpKid(getScpKid())
            .reconnectDeviceCallback(this::reconnectDevice)
            .setPin(true)
            .build();

    state.withCtap2(callback);
  }

  @Nullable
  @Override
  protected Byte getScpKid() {
    if (device.getTransport() == Transport.NFC) {
      return ScpKid.SCP11b;
    }
    return null;
  }

  protected PinUvAuthProtocol getPinUvAuthProtocol() {
    // default is protocol V2
    return new PinUvAuthProtocolV2();
  }
}

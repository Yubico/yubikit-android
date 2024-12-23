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

package com.yubico.yubikit.testing.mpe;

import static org.junit.Assert.assertFalse;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.testing.TestState;
import com.yubico.yubikit.testing.fido.FidoTestState;
import com.yubico.yubikit.testing.piv.PivTestState;

public class MpeTestState extends TestState {
  public static class Builder extends TestState.Builder<MpeTestState.Builder> {

    public Builder(YubiKeyDevice device, UsbPid usbPid) {
      super(device, usbPid);
    }

    @Override
    public Builder getThis() {
      return this;
    }

    public MpeTestState build() throws Throwable {
      return new MpeTestState(this);
    }
  }

  protected MpeTestState(MpeTestState.Builder builder) throws Throwable {
    super(builder);

    DeviceInfo deviceInfo = getDeviceInfo();
    assumeTrue("Cannot get device information", deviceInfo != null);
    assumeTrue("Not a MPE device", isMpe(deviceInfo));

    try (SmartCardConnection connection = openSmartCardConnection()) {
      final ManagementSession managementSession = getManagementSession(connection, scpParameters);
      managementSession.deviceReset();
    }

    // PIV and FIDO2 should not be reset blocked
    assertFalse(isPivResetBlocked());
    assertFalse(isFidoResetBlocked());
  }

  boolean isPivResetBlocked() {
    final DeviceInfo deviceInfo = getDeviceInfo();
    return (deviceInfo.getResetBlocked() & Capability.PIV.bit) == Capability.PIV.bit;
  }

  boolean isFidoResetBlocked() {
    final DeviceInfo deviceInfo = getDeviceInfo();
    return (deviceInfo.getResetBlocked() & Capability.FIDO2.bit) == Capability.FIDO2.bit;
  }

  public void withPiv(StatefulSessionCallback<PivSession, MpeTestState> callback) throws Throwable {
    try (SmartCardConnection connection = openSmartCardConnection()) {
      final PivSession piv = PivTestState.getPivSession(connection, scpParameters);
      assumeTrue("No PIV support", piv != null);
      callback.invoke(piv, this);
    }
    reconnect();
  }

  public void withCtap2(TestState.StatefulSessionCallback<Ctap2Session, MpeTestState> callback)
      throws Throwable {
    try (YubiKeyConnection connection = openConnection()) {
      final Ctap2Session ctap2 = FidoTestState.getCtap2Session(connection);
      assumeTrue("No CTAP2 support", ctap2 != null);
      callback.invoke(ctap2, this);
    }
    reconnect();
  }
}

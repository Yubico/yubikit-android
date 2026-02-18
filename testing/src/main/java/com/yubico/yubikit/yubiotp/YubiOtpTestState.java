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

package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.TestState;
import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.management.DeviceInfo;
import java.util.List;
import org.jspecify.annotations.Nullable;

@org.jspecify.annotations.NullMarked
public class YubiOtpTestState extends TestState {
  public final @Nullable Integer deviceSerial;

  public static class Builder extends TestState.Builder<YubiOtpTestState.Builder> {
    public Builder(
        YubiKeyDevice device,
        List<Class<? extends YubiKeyConnection>> supportedConnectionTypes,
        UsbPid usbPid) {
      super(device, supportedConnectionTypes, usbPid);
    }

    @Override
    public Builder getThis() {
      return this;
    }

    public YubiOtpTestState build() throws Throwable {
      return new YubiOtpTestState(this);
    }
  }

  protected YubiOtpTestState(YubiOtpTestState.Builder builder) throws Throwable {
    super(builder);
    DeviceInfo deviceInfo = getDeviceInfo();
    deviceSerial = deviceInfo != null ? deviceInfo.getSerialNumber() : null;

    try (YubiKeyConnection connection = openConnection()) {
      YubiOtpSession otp = getYubiOtpSession(connection, scpParameters.getKeyParams());
      for (Slot s : Slot.values()) {
        if (otp.getConfigurationState().isConfigured(s)) {
          otp.deleteConfiguration(s, null);
        }
      }
    }
  }

  public void withYubiOtp(StatefulSessionCallback<YubiOtpSession, YubiOtpTestState> callback)
      throws Throwable {

    try (YubiKeyConnection connection = openConnection()) {
      callback.invoke(getYubiOtpSession(connection, scpParameters.getKeyParams()), this);
    }
    reconnect();
  }
}

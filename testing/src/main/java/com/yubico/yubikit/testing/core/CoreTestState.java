/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.testing.core;

import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;
import com.yubico.yubikit.testing.TestState;
import java.io.IOException;
import org.jspecify.annotations.Nullable;

public class CoreTestState extends TestState {

  public static class Builder extends TestState.Builder<Builder> {

    public Builder(YubiKeyDevice device, UsbPid usbPid) {
      super(device, usbPid);
    }

    @Override
    public Builder getThis() {
      return this;
    }

    public CoreTestState build() throws Throwable {
      return new CoreTestState(this);
    }
  }

  public CoreTestState(Builder builder) throws Throwable {
    super(builder);
  }

  public void withDeviceCallback(StatefulDeviceCallback<CoreTestState> callback) throws Throwable {
    callback.invoke(this);
  }

  public void withDevice(YubiKeyDeviceCallback callback) throws Throwable {
    try {
      callback.invoke(currentDevice);
    } finally {
      reconnect();
    }
  }

  public void withSecurityDomain(
      @Nullable ScpKeyParams scpKeyParams, SessionCallback<SecurityDomainSession> callback)
      throws Throwable {
    try (SmartCardConnection connection = openSmartCardConnection()) {
      callback.invoke(getSecurityDomainSession(connection, scpKeyParams));
    }
    reconnect();
  }

  public <R> R withSecurityDomain(
      @Nullable ScpKeyParams scpKeyParams, SessionCallbackT<SecurityDomainSession, R> callback)
      throws Throwable {
    R result;
    try (SmartCardConnection connection = openSmartCardConnection()) {
      result = callback.invoke(getSecurityDomainSession(connection, scpKeyParams));
    }
    reconnect();
    return result;
  }

  @Nullable
  public static SecurityDomainSession getSecurityDomainSession(
      SmartCardConnection connection, @Nullable ScpKeyParams scpKeyParams) throws IOException {
    try {
      return new SecurityDomainSession(connection, scpKeyParams);
    } catch (ApplicationNotAvailableException ignored) {
      // no Security Domain support
    }
    return null;
  }
}

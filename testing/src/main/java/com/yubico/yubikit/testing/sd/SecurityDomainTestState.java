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

package com.yubico.yubikit.testing.sd;

import static org.junit.Assert.assertNull;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;
import com.yubico.yubikit.testing.TestState;
import java.io.IOException;
import org.jspecify.annotations.Nullable;

public class SecurityDomainTestState extends TestState {

  public static class Builder extends TestState.Builder<SecurityDomainTestState.Builder> {

    public Builder(YubiKeyDevice device, UsbPid usbPid) {
      super(device, usbPid);
    }

    @Override
    public Builder getThis() {
      return this;
    }

    public SecurityDomainTestState build() throws Throwable {
      return new SecurityDomainTestState(this);
    }
  }

  protected SecurityDomainTestState(Builder builder) throws Throwable {
    super(builder);

    try (SmartCardConnection connection = openSmartCardConnection()) {
      assumeTrue("Key does not support smart card connection", connection != null);
      SecurityDomainSession sd = getSecurityDomainSession(connection);
      assumeTrue("Security domain not supported", sd != null);
      assertNull("These tests expect kid to be null", scpParameters.getKid());
    }
  }

  public void withDeviceCallback(StatefulDeviceCallback<SecurityDomainTestState> callback)
      throws Throwable {
    callback.invoke(this);
  }

  public void withSecurityDomain(SessionCallback<SecurityDomainSession> callback) throws Throwable {
    try (SmartCardConnection connection = openSmartCardConnection()) {
      callback.invoke(getSecurityDomainSession(connection));
    }
    reconnect();
  }

  public <R> R withSecurityDomain(SessionCallbackT<SecurityDomainSession, R> callback)
      throws Throwable {
    R result;
    try (SmartCardConnection connection = openSmartCardConnection()) {
      result = callback.invoke(getSecurityDomainSession(connection));
    }
    reconnect();
    return result;
  }

  public void withSecurityDomain(
      ScpKeyParams scpKeyParams, SessionCallback<SecurityDomainSession> callback) throws Throwable {
    try (SmartCardConnection connection = openSmartCardConnection()) {
      callback.invoke(getSecurityDomainSession(scpKeyParams, connection));
    }
    reconnect();
  }

  public <R> R withSecurityDomain(
      ScpKeyParams scpKeyParams, SessionCallbackT<SecurityDomainSession, R> callback)
      throws Throwable {
    R result;
    try (SmartCardConnection connection = openSmartCardConnection()) {
      result = callback.invoke(getSecurityDomainSession(scpKeyParams, connection));
    }
    reconnect();
    return result;
  }

  @Nullable
  protected SecurityDomainSession getSecurityDomainSession(SmartCardConnection connection)
      throws IOException {
    try {
      return new SecurityDomainSession(connection, scpParameters.getKeyParams());
    } catch (ApplicationNotAvailableException ignored) {
      // no Security Domain support
    }
    return null;
  }

  @Nullable
  public static SecurityDomainSession getSecurityDomainSession(
      ScpKeyParams scpKeyParams, SmartCardConnection connection) throws IOException {
    try {
      return new SecurityDomainSession(connection, scpKeyParams);
    } catch (ApplicationNotAvailableException ignored) {
      // no Security Domain support
    }
    return null;
  }
}

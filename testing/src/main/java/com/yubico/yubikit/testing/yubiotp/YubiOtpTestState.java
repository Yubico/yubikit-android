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

package com.yubico.yubikit.testing.yubiotp;

import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.yubiotp.YubiOtpSession;
import com.yubico.yubikit.testing.ScpParameters;
import com.yubico.yubikit.testing.TestState;

import java.io.IOException;

import javax.annotation.Nullable;

public class YubiOtpTestState extends TestState {
  public boolean isFipsApproved;
  public char[] password;

  public static class Builder extends TestState.Builder<Builder> {

    public Builder(YubiKeyDevice device, UsbPid usbPid) {
      super(device, usbPid);
    }

    @Override
    public Builder getThis() {
      return this;
    }

    public com.yubico.yubikit.testing.yubiotp.YubiOtpTestState build() throws Throwable {
      return new com.yubico.yubikit.testing.yubiotp.YubiOtpTestState(this);
    }
  }

  protected YubiOtpTestState(Builder builder) throws Throwable {
    super(builder);

    password = "".toCharArray();

    boolean isYubiOtpFipsCapable = isFipsCapable(Capability.OTP);

    if (scpParameters.getKid() == null && isYubiOtpFipsCapable) {
//      assumeTrue("Trying to use OTP FIPS capable device over NFC without SCP", isUsbTransport());
    }

    if (scpParameters.getKid() != null) {
      // skip the test if the connected key does not provide matching SCP keys
      assumeTrue(
          "No matching key params found for required kid", scpParameters.getKeyParams() != null);
    }

    try (SmartCardConnection connection = openSmartCardConnection()) {
      assumeTrue("Smart card not available", connection != null);

      YubiOtpSession oath = getYubiOtpSession(connection, scpParameters);

//      assumeTrue("OTP not available", oath != null);
//      oath.reset();
//
//      final char[] complexPassword = "11234567".toCharArray();
//      oath.setPassword(complexPassword);
//      password = complexPassword;
    }

    isFipsApproved = isFipsApproved(Capability.OTP);

    // after changing the OTP password, we expect a FIPS capable device to be FIPS approved
    if (isYubiOtpFipsCapable) {
      assertTrue("Device not OTP FIPS approved as expected", isFipsApproved);
    }
  }

  public void withDeviceCallback(StatefulDeviceCallback<com.yubico.yubikit.testing.yubiotp.YubiOtpTestState> callback) throws Throwable {
    callback.invoke(this);
  }

  public void withYubiOtp(StatefulSessionCallback<YubiOtpSession, com.yubico.yubikit.testing.yubiotp.YubiOtpTestState> callback)
      throws Throwable {
    try (SmartCardConnection connection = openSmartCardConnection()) {
      callback.invoke(getYubiOtpSession(connection, scpParameters), this);
    }
    reconnect();
  }

  public void withYubiOtp(SessionCallback<YubiOtpSession> callback) throws Throwable {
    try (SmartCardConnection connection = openSmartCardConnection()) {
      callback.invoke(getYubiOtpSession(connection, scpParameters));
    }
    reconnect();
  }

  @Nullable
  public static YubiOtpSession getYubiOtpSession(
      SmartCardConnection connection, ScpParameters scpParameters) throws IOException {
    try {
      return new YubiOtpSession(connection, scpParameters.getKeyParams());
    } catch (ApplicationNotAvailableException ignored) {
      // no OTP support
    }
    return null;
  }
}

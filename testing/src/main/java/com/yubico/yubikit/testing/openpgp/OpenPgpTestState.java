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

package com.yubico.yubikit.testing.openpgp;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.openpgp.OpenPgpSession;
import com.yubico.yubikit.openpgp.Pw;
import com.yubico.yubikit.testing.TestState;
import java.util.Collections;
import org.junit.Assume;

public class OpenPgpTestState extends TestState {

  private static final char[] COMPLEX_USER_PIN = "112345678".toCharArray();
  private static final char[] COMPLEX_ADMIN_PIN = "112345678".toCharArray();

  public final boolean isFipsApproved;
  public char[] defaultUserPin;
  public char[] defaultAdminPin;

  public static class Builder extends TestState.Builder<OpenPgpTestState.Builder> {

    public Builder(YubiKeyDevice device, UsbPid usbPid) {
      super(device, Collections.singletonList(SmartCardConnection.class), usbPid);
    }

    @Override
    public Builder getThis() {
      return this;
    }

    public OpenPgpTestState build() throws Throwable {
      return new OpenPgpTestState(this);
    }
  }

  protected OpenPgpTestState(OpenPgpTestState.Builder builder) throws Throwable {
    super(builder);

    defaultUserPin = Pw.DEFAULT_USER_PIN;
    defaultAdminPin = Pw.DEFAULT_ADMIN_PIN;

    DeviceInfo deviceInfo = getDeviceInfo();
    boolean isOpenPgpFipsCapable = isFipsCapable(deviceInfo, Capability.OPENPGP);
    boolean hasPinComplexity = deviceInfo != null && deviceInfo.getPinComplexity();

    if (scpParameters.getKid() == null && isOpenPgpFipsCapable) {
      Assume.assumeTrue(
          "Trying to use OpenPgp FIPS capable device over NFC without SCP", isUsbTransport());
    }

    if (scpParameters.getKid() != null) {
      // skip the test if the connected key does not provide matching SCP keys
      Assume.assumeTrue(
          "No matching key params found for required kid", scpParameters.getKeyParams() != null);
    }

    try (YubiKeyConnection connection = openConnection()) {
      assumeTrue("Smart card not available", connection != null);

      OpenPgpSession openPgp =
          getSession(connection, scpParameters.getKeyParams(), OpenPgpSession::new);

      assumeTrue("OpenPGP not available", openPgp != null);
      openPgp.reset();

      if (hasPinComplexity) {
        // only use complex pins if pin complexity is required
        openPgp.changeUserPin(defaultUserPin, COMPLEX_USER_PIN);
        openPgp.changeAdminPin(defaultAdminPin, COMPLEX_ADMIN_PIN);
        defaultUserPin = COMPLEX_USER_PIN;
        defaultAdminPin = COMPLEX_ADMIN_PIN;
      }
    }

    deviceInfo = getDeviceInfo();
    isFipsApproved = isFipsApproved(deviceInfo, Capability.OPENPGP);

    // after changing the user and admin PINs, we expect a FIPS capable device
    // to be FIPS approved
    if (isOpenPgpFipsCapable) {
      assertNotNull(deviceInfo);
      assertTrue("Device not OpenPgp FIPS approved as expected", isFipsApproved);
    }
  }

  public void withOpenPgp(StatefulSessionCallback<OpenPgpSession, OpenPgpTestState> callback)
      throws Throwable {
    try (YubiKeyConnection connection = openConnection()) {
      callback.invoke(
          getSession(connection, scpParameters.getKeyParams(), OpenPgpSession::new), this);
    }
    reconnect();
  }
}

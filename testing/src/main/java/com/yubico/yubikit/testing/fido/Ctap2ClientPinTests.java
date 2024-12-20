/*
 * Copyright (C) 2020-2024 Yubico.
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

package com.yubico.yubikit.testing.fido;

import static com.yubico.yubikit.core.fido.CtapException.ERR_PIN_POLICY_VIOLATION;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.management.DeviceInfo;
import java.util.Objects;

public class Ctap2ClientPinTests {
  public static void testClientPin(Ctap2Session session, FidoTestState state) throws Throwable {
    Integer permissions = ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA;
    String permissionRpId = "localhost";

    ClientPin pin = new ClientPin(session, state.getPinUvAuthProtocol());
    assertThat(pin.getPinUvAuth().getVersion(), is(state.getPinUvAuthProtocol().getVersion()));
    assertThat(pin.getPinRetries().getCount(), is(8));

    pin.changePin(TestData.PIN, TestData.OTHER_PIN);
    try {
      pin.getPinToken(TestData.PIN, permissions, permissionRpId);
      fail("Wrong PIN was accepted");
    } catch (CtapException e) {
      assertThat(e.getCtapError(), is(CtapException.ERR_PIN_INVALID));
    }
    assertThat(pin.getPinRetries().getCount(), is(7));

    assertThat(pin.getPinToken(TestData.OTHER_PIN, permissions, permissionRpId), notNullValue());
    assertThat(pin.getPinRetries().getCount(), is(8));
    pin.changePin(TestData.OTHER_PIN, TestData.PIN);
  }

  public static void testPinComplexity(FidoTestState state) throws Throwable {

    final DeviceInfo deviceInfo = state.getDeviceInfo();
    assumeTrue("Device does not support PIN complexity", deviceInfo != null);
    assumeTrue("Device does not require PIN complexity", deviceInfo.getPinComplexity());

    state.withCtap2(
        session -> {
          PinUvAuthProtocol pinUvAuthProtocol = new PinUvAuthProtocolV2();
          char[] defaultPin = "11234567".toCharArray();

          Ctap2Session.InfoData info = session.getCachedInfo();
          ClientPin pin = new ClientPin(session, pinUvAuthProtocol);
          boolean pinSet = Objects.requireNonNull((Boolean) info.getOptions().get("clientPin"));

          try {
            if (!pinSet) {
              pin.setPin(defaultPin);
            } else {
              pin.getPinToken(
                  defaultPin,
                  ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA,
                  "localhost");
            }
          } catch (ApduException e) {
            fail("Failed to set or use PIN. Reset the device and try again");
          }

          assertThat(pin.getPinUvAuth().getVersion(), is(pinUvAuthProtocol.getVersion()));
          assertThat(pin.getPinRetries().getCount(), is(8));

          char[] weakPin = "33333333".toCharArray();
          try {
            pin.changePin(defaultPin, weakPin);
            fail("Weak PIN was accepted");
          } catch (CtapException e) {
            assertThat(e.getCtapError(), is(ERR_PIN_POLICY_VIOLATION));
          }

          char[] strongPin = "STRONG PIN".toCharArray();
          pin.changePin(defaultPin, strongPin);
          pin.changePin(strongPin, defaultPin);

          assertThat(pin.getPinRetries().getCount(), is(8));
        });
  }
}

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
package com.yubico.yubikit.testing.piv;

import static com.yubico.yubikit.core.smartcard.SW.CONDITIONS_NOT_SATISFIED;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.piv.PivSession;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.Assert;

public class PivPinComplexityDeviceTests {

  /**
   * For this test, one needs a key with PIN complexity set on. The test will change PINs.
   *
   * <p>The test will verify that trying to set a weak PIN for PIV produces expected exceptions.
   *
   * @see DeviceInfo#getPinComplexity()
   */
  public static void testPinComplexity(PivSession piv, PivTestState state) throws Throwable {

    final DeviceInfo deviceInfo = state.getDeviceInfo();
    assumeTrue("Device does not support PIN complexity", deviceInfo != null);
    assumeTrue("Device does not require PIN complexity", deviceInfo.getPinComplexity());

    piv.reset();

    // the values in state are not valid after reset and we need to use
    // the default values
    piv.authenticate(PivTestState.DEFAULT_MANAGEMENT_KEY);
    piv.verifyPin(PivTestState.DEFAULT_PIN);

    MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(3));

    // try to change to pin which breaks PIN complexity
    char[] weakPin = "33333333".toCharArray();
    try {
      piv.changePin(PivTestState.DEFAULT_PIN, weakPin);
      Assert.fail("Set weak PIN");
    } catch (ApduException apduException) {
      if (apduException.getSw() != CONDITIONS_NOT_SATISFIED) {
        Assert.fail("Unexpected exception:" + apduException.getMessage());
      }
    } catch (Exception e) {
      Assert.fail("Unexpected exception:" + e.getMessage());
    }

    piv.verifyPin(PivTestState.DEFAULT_PIN);

    // change to complex pin
    char[] complexPin = "CMPLXPIN".toCharArray();
    try {
      piv.changePin(PivTestState.DEFAULT_PIN, complexPin);
    } catch (Exception e) {
      Assert.fail("Unexpected exception:" + e.getMessage());
    }

    piv.verifyPin(complexPin);

    // the value of default PIN in the state is correct for pin complexity settings
    piv.changePin(complexPin, state.pin);
  }
}

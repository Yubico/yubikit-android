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

import com.yubico.yubikit.SmokeTest;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.framework.YubiOtpInstrumentedTests;
import java.util.Collections;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.categories.Category;

public class YubiOtpOverCcidTests extends YubiOtpInstrumentedTests {

  @Before
  public void setupCcidOnly() {
    connectionTypes = Collections.singletonList(SmartCardConnection.class);
  }

  @Test
  public void testSlotTouchTriggered() throws Throwable {
    withYubiOtpSession(
        (otp, state) -> {
          YubiOtpDeviceTests.testSlotTouchTriggered(otp, state, Slot.ONE);
          YubiOtpDeviceTests.testSlotTouchTriggered(otp, state, Slot.TWO);
        });
  }

  @Test
  @Category(SmokeTest.class)
  public void testSwitchTransports() throws Throwable {
    withYubiOtpSession(YubiOtpDeviceTests::testSlotConfigured);
    connectionTypes = Collections.singletonList(OtpConnection.class);
    withYubiOtpSession(YubiOtpDeviceTests::testSlotConfigured);
    connectionTypes = Collections.singletonList(SmartCardConnection.class);
    withYubiOtpSession(YubiOtpDeviceTests::testSlotConfigured);
    connectionTypes = Collections.singletonList(OtpConnection.class);
    withYubiOtpSession(YubiOtpDeviceTests::testCalculateHmacSha1);
  }
}

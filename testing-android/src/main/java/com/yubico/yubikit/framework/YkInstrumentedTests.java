/*
 * Copyright (C) 2022-2026 Yubico.
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

package com.yubico.yubikit.framework;

import androidx.test.ext.junit.rules.ActivityScenarioRule;
import com.yubico.yubikit.TestActivity;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice;
import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyDevice;
import org.jspecify.annotations.Nullable;
import org.junit.After;
import org.junit.AssumptionViolatedException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.rules.TestName;
import org.junit.rules.TestWatcher;
import org.junit.runner.Description;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class YkInstrumentedTests {

  private static final Logger logger = LoggerFactory.getLogger(YkInstrumentedTests.class);

  private @Nullable TestActivity activity;
  protected @Nullable YubiKeyDevice device = null;
  protected @Nullable UsbPid usbPid = null;

  @Rule public final TestName name = new TestName();

  /**
   * Logs why a test was skipped; AGP reports an assumption failure as a bare {@code <skipped/>}
   * with no message, so a whole suite skipping reads like a suite that ran.
   */
  @Rule
  public final TestWatcher skipReasonLogger =
      new TestWatcher() {
        @Override
        protected void skipped(AssumptionViolatedException e, Description description) {
          logger.error("SKIPPED {}: {}", description.getMethodName(), e.getMessage());
        }
      };

  @Rule
  public final ActivityScenarioRule<TestActivity> scenarioRule =
      new ActivityScenarioRule<>(TestActivity.class);

  @Before
  public void getYubiKey() throws InterruptedException {
    scenarioRule.getScenario().onActivity((TestActivity activity) -> this.activity = activity);
    TestActivity currentActivity = this.activity;
    if (currentActivity != null) {
      device = currentActivity.awaitSession(getClass().getSimpleName(), name.getMethodName());
      usbPid = device instanceof UsbYubiKeyDevice ? ((UsbYubiKeyDevice) device).getPid() : null;
    }
  }

  @After
  public void after() throws InterruptedException {
    releaseYubiKey();
  }

  public void releaseYubiKey() throws InterruptedException {
    if (activity != null && device != null) {
      activity.returnSession(device);
    }
    device = null;
    activity = null;
    usbPid = null;
  }

  protected YubiKeyDevice reconnectDevice() {
    try {
      YubiKeyDevice currentDevice = this.device;
      if (currentDevice != null && currentDevice.getTransport() == Transport.NFC) {
        releaseYubiKey();
        getYubiKey();
      }
      if (device == null) {
        throw new IllegalStateException("Device not available");
      }
      return device;
    } catch (InterruptedException e) {
      throw new RuntimeException("Failure during reconnect", e);
    }
  }

  @Nullable
  protected Byte getScpKid() {
    return null;
  }
}

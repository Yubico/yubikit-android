/*
 * Copyright (C) 2022-2025 Yubico.
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
package com.yubico.yubikit.testing.desktop.framework;

import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.desktop.CompositeDevice;
import com.yubico.yubikit.testing.AllowList;
import com.yubico.yubikit.testing.desktop.DesktopAllowListProvider;
import com.yubico.yubikit.testing.desktop.DesktopTestDriver;
import org.jetbrains.annotations.Nullable;
import org.junit.Rule;
import org.junit.rules.ExternalResource;
import org.junit.rules.TestName;

public class YKInstrumentedTests {

  private final DesktopTestDriver testDriver = new DesktopTestDriver();

  protected YubiKeyDevice device = null;
  protected UsbPid usbPid = null;

  @Rule public final TestName name = new TestName();

  private static final AllowList allowList = new AllowList(new DesktopAllowListProvider());

  @Rule
  public final ExternalResource externalResource =
      new ExternalResource() {

        @Override
        protected void before() {
          getDevice();
        }

        @Override
        protected void after() {
          releaseDevice();
        }
      };

  protected YubiKeyDevice reconnectDevice() {
    releaseDevice();
    getDevice();
    return device;
  }

  @Nullable
  protected Byte getScpKid() {
    return null;
  }

  private void getDevice() {
    try {
      device = testDriver.awaitSession();
      if (device instanceof CompositeDevice) {
        CompositeDevice compositeDevice = (CompositeDevice) device;
        usbPid = compositeDevice.getPidGroup().getPid();
      }
      allowList.verify(device, usbPid);
    } catch (InterruptedException interruptedException) {
      throw new RuntimeException("awaitSession failed", interruptedException);
    }
  }

  private void releaseDevice() {
    testDriver.returnSession(device);
    device = null;
  }
}

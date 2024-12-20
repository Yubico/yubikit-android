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

package com.yubico.yubikit.testing.management;

import com.yubico.yubikit.management.DeviceConfig;
import com.yubico.yubikit.management.ManagementSession;
import org.junit.Assert;
import org.junit.Assume;

public class ManagementDeviceTests {
  public static void testNfcRestricted(ManagementSession managementSession) throws Exception {
    Assume.assumeTrue(managementSession.getVersion().isAtLeast(5, 7, 0));
    managementSession.updateDeviceConfig(
        new DeviceConfig.Builder().nfcRestricted(true).build(), false, null, null);

    Assert.assertEquals(
        Boolean.TRUE, managementSession.getDeviceInfo().getConfig().getNfcRestricted());
  }
}

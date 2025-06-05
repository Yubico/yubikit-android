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

package com.yubico.yubikit.management;

import static com.yubico.yubikit.management.TestUtil.assertByteEquals;
import static com.yubico.yubikit.management.TestUtil.assertIntegerEquals;
import static com.yubico.yubikit.management.TestUtil.assertIsTrue;
import static com.yubico.yubikit.management.TestUtil.assertShortEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import com.yubico.yubikit.core.Transport;
import org.junit.Test;

public class DeviceConfigBuilderTest {
  @Test
  public void testDefaults() {
    DeviceConfig defaultConfig = new DeviceConfig.Builder().build();
    assertNull(defaultConfig.getEnabledCapabilities(Transport.USB));
    assertNull(defaultConfig.getEnabledCapabilities(Transport.NFC));
    assertNull(defaultConfig.getAutoEjectTimeout());
    assertNull(defaultConfig.getChallengeResponseTimeout());
    assertNull(defaultConfig.getDeviceFlags());
    assertNull(defaultConfig.getNfcRestricted());
  }

  @Test
  public void testBuild() {
    DeviceConfig config =
        new DeviceConfig.Builder()
            .enabledCapabilities(Transport.USB, 12345)
            .enabledCapabilities(Transport.NFC, 67890)
            .autoEjectTimeout((short) 128)
            .challengeResponseTimeout((byte) 55)
            .deviceFlags(98765)
            .nfcRestricted(true)
            .build();
    assertIntegerEquals(12345, config.getEnabledCapabilities(Transport.USB));
    assertIntegerEquals(67890, config.getEnabledCapabilities(Transport.NFC));
    assertShortEquals(128, config.getAutoEjectTimeout());
    assertByteEquals(55, config.getChallengeResponseTimeout());
    assertIntegerEquals(98765, config.getDeviceFlags());
    assertNotNull(config.getNfcRestricted());
    assertIsTrue(config.getNfcRestricted());
  }
}

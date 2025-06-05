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
import static com.yubico.yubikit.management.TestUtil.assertIsFalse;
import static com.yubico.yubikit.management.TestUtil.assertIsTrue;
import static com.yubico.yubikit.management.TestUtil.assertShortEquals;
import static com.yubico.yubikit.management.TestUtil.defaultVersion;
import static com.yubico.yubikit.management.TestUtil.emptyTlvs;
import static com.yubico.yubikit.management.TestUtil.tlvs;

import org.junit.Test;

public class DeviceConfigTest {

  @Test
  public void testParseNfcRestricted() {
    assertIsFalse(defaultConfig().getNfcRestricted());
    assertIsFalse(configOf(0x17, new byte[] {0x00}).getNfcRestricted());
    assertIsFalse(configOf(0x17, new byte[] {0x02}).getNfcRestricted());
    assertIsTrue(configOf(0x17, new byte[] {0x01}).getNfcRestricted());
  }

  @Test
  public void testParseAutoEjectTimeout() {
    assertShortEquals(0, defaultConfig().getAutoEjectTimeout());
    assertShortEquals(16384, configOf(0x06, new byte[] {0x40, 0x00}).getAutoEjectTimeout());
    assertShortEquals(-32768, configOf(0x06, new byte[] {(byte) 0x80, 0x00}).getAutoEjectTimeout());
  }

  @Test
  public void testParseChallengeResponseTimeout() {
    assertByteEquals(0, defaultConfig().getChallengeResponseTimeout());
    assertByteEquals(50, configOf(0x07, new byte[] {0x32}).getChallengeResponseTimeout());
    assertByteEquals(-128, configOf(0x07, new byte[] {(byte) 0x80}).getChallengeResponseTimeout());
  }

  @Test
  public void testParseDeviceFlags() {
    assertIntegerEquals(0, defaultConfig().getDeviceFlags());
    assertIntegerEquals(987654, configOf(0x08, new byte[] {0x0F, 0x12, 0x06}).getDeviceFlags());
  }

  private DeviceConfig defaultConfig() {
    return DeviceInfo.parseTlvs(emptyTlvs(), defaultVersion).getConfig();
  }

  private DeviceConfig configOf(int tag, byte[] data) {
    return DeviceInfo.parseTlvs(tlvs(tag, data), defaultVersion).getConfig();
  }
}

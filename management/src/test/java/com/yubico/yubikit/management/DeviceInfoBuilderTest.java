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

package com.yubico.yubikit.management;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class DeviceInfoBuilderTest {

  @Test
  public void testDefaults() {
    assertEquals(defaultConfig(), defaultInfo().getConfig());
    assertNull(defaultInfo().getSerialNumber());
    assertEquals(new Version(0, 0, 0), defaultInfo().getVersion());
    assertEquals(FormFactor.UNKNOWN, defaultInfo().getFormFactor());
    assertEquals(0, defaultInfo().getSupportedCapabilities(Transport.USB));
    assertEquals(0, defaultInfo().getSupportedCapabilities(Transport.NFC));
    assertFalse(defaultInfo().isLocked());
    assertFalse(defaultInfo().isFips());
    assertFalse(defaultInfo().isSky());
    assertFalse(defaultInfo().getPinComplexity());
    assertFalse(defaultInfo().hasTransport(Transport.USB));
    assertFalse(defaultInfo().hasTransport(Transport.NFC));
  }

  @Test
  public void testConstruction() {
    Map<Transport, Integer> supportedCapabilities = new HashMap<>();
    supportedCapabilities.put(Transport.USB, 123);
    supportedCapabilities.put(Transport.NFC, 456);
    DeviceInfo deviceInfo =
        new DeviceInfo.Builder()
            .config(defaultConfig())
            .serialNumber(987654321)
            .version(new Version(3, 1, 1))
            .formFactor(FormFactor.USB_A_KEYCHAIN)
            .supportedCapabilities(supportedCapabilities)
            .isLocked(true)
            .isFips(true)
            .isSky(true)
            .pinComplexity(true)
            .build();
    assertEquals(defaultConfig(), deviceInfo.getConfig());
    assertEquals(Integer.valueOf(987654321), deviceInfo.getSerialNumber());
    assertEquals(new Version(3, 1, 1), deviceInfo.getVersion());
    assertEquals(FormFactor.USB_A_KEYCHAIN, deviceInfo.getFormFactor());
    assertEquals(123, deviceInfo.getSupportedCapabilities(Transport.USB));
    assertEquals(456, deviceInfo.getSupportedCapabilities(Transport.NFC));
    assertTrue(deviceInfo.isLocked());
    assertTrue(deviceInfo.isFips());
    assertTrue(deviceInfo.isSky());
    assertTrue(deviceInfo.getPinComplexity());
    assertTrue(deviceInfo.hasTransport(Transport.USB));
    assertTrue(deviceInfo.hasTransport(Transport.NFC));
  }

  @Test
  public void testPartNumber() {
    assertEquals("", defaultInfo().getPartNumber());
    assertEquals("", new DeviceInfo.Builder().partNumber("").build().getPartNumber());
    assertEquals(
        "0123456789ABCDEF",
        new DeviceInfo.Builder().partNumber("0123456789ABCDEF").build().getPartNumber());
  }

  @Test
  public void testFipsCapable() {
    assertEquals(0, defaultInfo().getFipsCapable());
    DeviceInfo deviceInfo = new DeviceInfo.Builder().fipsCapable(145).build();
    assertEquals(145, deviceInfo.getFipsCapable());
  }

  @Test
  public void testFipsApproved() {
    assertEquals(0, defaultInfo().getFipsApproved());
    DeviceInfo deviceInfo = new DeviceInfo.Builder().fipsApproved(43445).build();
    assertEquals(43445, deviceInfo.getFipsApproved());
  }

  @Test
  public void testResetBlocked() {
    assertEquals(0, defaultInfo().getResetBlocked());
    DeviceInfo deviceInfo = new DeviceInfo.Builder().resetBlocked(874344).build();
    assertEquals(874344, deviceInfo.getResetBlocked());
  }

  @Test
  public void testFpsVersion() {
    assertNull(defaultInfo().getFpsVersion());
    DeviceInfo deviceInfo = new DeviceInfo.Builder().fpsVersion(new Version(5, 4, 3)).build();
    assertEquals(new Version(5, 4, 3), deviceInfo.getFpsVersion());
  }

  @Test
  public void testStmVersion() {
    assertNull(defaultInfo().getStmVersion());
    DeviceInfo deviceInfo = new DeviceInfo.Builder().stmVersion(new Version(5, 6, 2)).build();
    assertEquals(new Version(5, 6, 2), deviceInfo.getStmVersion());
  }

  @Test
  public void testVersionQualifier() {
    VersionQualifier defaultQualifier = defaultInfo().getVersionQualifier();
    assertEquals(
        new VersionQualifier(new Version(0, 0, 0), VersionQualifier.Type.FINAL, 0),
        defaultQualifier);

    DeviceInfo deviceInfo =
        new DeviceInfo.Builder()
            .version(new Version(3, 0, 0))
            .versionQualifier(
                new VersionQualifier(new Version(5, 6, 2), VersionQualifier.Type.ALPHA, 15))
            .build();

    assertEquals(
        new VersionQualifier(new Version(5, 6, 2), VersionQualifier.Type.ALPHA, 15),
        deviceInfo.getVersionQualifier());

    assertEquals(new Version(3, 0, 0), deviceInfo.getVersion());

    assertEquals("5.6.2.alpha.15", deviceInfo.getVersionQualifier().toString());
  }

  private DeviceInfo defaultInfo() {
    return new DeviceInfo.Builder().build();
  }

  private DeviceConfig defaultConfig() {
    return new DeviceConfig.Builder().build();
  }
}

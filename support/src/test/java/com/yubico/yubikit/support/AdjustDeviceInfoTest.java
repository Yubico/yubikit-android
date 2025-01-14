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

package com.yubico.yubikit.support;

import static com.yubico.yubikit.support.TestUtil.config;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbInterface;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.YubiKeyType;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.FormFactor;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Test;

public class AdjustDeviceInfoTest {

  @Test
  public void testConfigDeviceFlags() {
    assertNull(adjustedInfo(i -> {}).getConfig().getDeviceFlags());

    assertEquals(
        Integer.valueOf(123456),
        adjustedInfo(i -> i.config(config(c -> c.deviceFlags(123456))))
            .getConfig()
            .getDeviceFlags());
  }

  @Test
  public void testConfigAutoEjectTimeout() {
    assertNull(adjustedInfo(i -> {}).getConfig().getAutoEjectTimeout());

    assertEquals(
        Short.valueOf((short) 13288),
        adjustedInfo(i -> i.config(config(c -> c.autoEjectTimeout((short) 13288))))
            .getConfig()
            .getAutoEjectTimeout());
  }

  @Test
  public void testConfigChallengeResponseTimeout() {
    assertNull(adjustedInfo(i -> {}).getConfig().getChallengeResponseTimeout());

    assertEquals(
        Byte.valueOf((byte) 84),
        adjustedInfo(i -> i.config(config(c -> c.challengeResponseTimeout((byte) 84))))
            .getConfig()
            .getChallengeResponseTimeout());
  }

  @Test
  public void testConfigEnabledCapabilitiesUsb() {
    assertNull(adjustedInfo(i -> {}).getConfig().getEnabledCapabilities(Transport.USB));

    DeviceInfo info =
        adjustedInfo(i -> i.config(config(c -> c.enabledCapabilities(Transport.USB, 124))));
    assertEquals(Integer.valueOf(124), info.getConfig().getEnabledCapabilities(Transport.USB));
    assertNull(info.getConfig().getEnabledCapabilities(Transport.NFC));
  }

  @Test
  public void testConfigEnabledCapabilitiesNfc() {
    assertNull(adjustedInfo(i -> {}).getConfig().getEnabledCapabilities(Transport.NFC));

    DeviceInfo info =
        adjustedInfo(i -> i.config(config(c -> c.enabledCapabilities(Transport.NFC, 552))));
    assertEquals(Integer.valueOf(552), info.getConfig().getEnabledCapabilities(Transport.NFC));
    assertNull(info.getConfig().getEnabledCapabilities(Transport.USB));
  }

  @Test
  public void testConfigNfcRestricted() {
    assertNull(adjustedInfo(i -> {}).getConfig().getNfcRestricted());

    assertEquals(
        TRUE,
        adjustedInfo(i -> i.config(config(c -> c.nfcRestricted(true))))
            .getConfig()
            .getNfcRestricted());

    assertEquals(
        FALSE,
        adjustedInfo(i -> i.config(config(c -> c.nfcRestricted(false))))
            .getConfig()
            .getNfcRestricted());
  }

  @Test
  public void testVersion() {
    assertEquals(new Version(0, 0, 0), adjustedInfo(i -> {}).getVersion());

    assertEquals(
        new Version(5, 7, 1), adjustedInfo(i -> i.version(new Version(5, 7, 1))).getVersion());
  }

  @Test
  public void testFormFactor() {
    assertEquals(FormFactor.UNKNOWN, adjustedInfo(i -> {}).getFormFactor());

    for (FormFactor formFactor : FormFactor.values()) {
      assertEquals(formFactor, adjustedInfo(i -> i.formFactor(formFactor)).getFormFactor());
    }
  }

  @Test
  public void testSerialNumber() {
    assertNull(adjustedInfo(i -> {}).getSerialNumber());

    assertEquals(
        Integer.valueOf(232325454), adjustedInfo(i -> i.serialNumber(232325454)).getSerialNumber());
  }

  @Test
  public void testIsLocked() {
    assertFalse(adjustedInfo(i -> {}).isLocked());

    assertTrue(adjustedInfo(i -> i.isLocked(true)).isLocked());

    assertFalse(adjustedInfo(i -> i.isLocked(false)).isLocked());
  }

  @Test
  public void testIsFips() {
    assertFalse(adjustedInfo(i -> {}).isFips());

    assertTrue(adjustedInfo(i -> i.isFips(true)).isFips());

    assertFalse(adjustedInfo(i -> i.isFips(false)).isFips());
  }

  @Test
  public void testIsSky() {
    assertFalse(adjustedInfo(i -> {}).isSky());

    assertTrue(adjustedInfo(i -> i.isSky(true)).isSky());

    assertTrue(adjustedInfo(i -> i.isSky(false), YubiKeyType.SKY, 0).isSky());

    assertFalse(adjustedInfo(i -> i.isSky(false)).isSky());
  }

  @Test
  public void testFipsCapable() {
    assertEquals(0, adjustedInfo(i -> {}).getFipsCapable());

    assertEquals(16384, adjustedInfo(i -> i.fipsCapable(16384)).getFipsCapable());
  }

  @Test
  public void testFipsApproved() {
    assertEquals(0, adjustedInfo(i -> {}).getFipsApproved());

    assertEquals(65535, adjustedInfo(i -> i.fipsApproved(65535)).getFipsApproved());
  }

  @Test
  public void testPartNumber() {
    assertEquals("", adjustedInfo(i -> {}).getPartNumber());

    assertEquals(
        "0102030405060708", adjustedInfo(i -> i.partNumber("0102030405060708")).getPartNumber());
  }

  @Test
  public void testPinComplexity() {
    assertFalse(adjustedInfo(i -> {}).getPinComplexity());

    assertTrue(adjustedInfo(i -> i.pinComplexity(true)).getPinComplexity());

    assertFalse(adjustedInfo(i -> i.pinComplexity(false)).getPinComplexity());
  }

  @Test
  public void testResetBlocked() {
    assertEquals(0, adjustedInfo(i -> {}).getResetBlocked());

    assertEquals(22647, adjustedInfo(i -> i.resetBlocked(22647)).getResetBlocked());
  }

  @Test
  public void testFpsVersion() {
    assertNull(adjustedInfo(i -> {}).getFpsVersion());

    assertEquals(
        new Version(1, 4, 2),
        adjustedInfo(i -> i.fpsVersion(new Version(1, 4, 2))).getFpsVersion());
  }

  @Test
  public void testStmVersion() {
    assertNull(adjustedInfo(i -> {}).getStmVersion());

    assertEquals(
        new Version(2, 4, 2),
        adjustedInfo(i -> i.stmVersion(new Version(2, 4, 2))).getStmVersion());
  }

  @Test
  public void testSupportedCapabilities() {
    // USB
    assertEquals(0, adjustedInfo(i -> {}).getSupportedCapabilities(Transport.USB));

    Map<Transport, Integer> supportedUsbCapabilities = new HashMap<>();
    supportedUsbCapabilities.put(Transport.USB, 4096);
    assertEquals(
        4096,
        adjustedInfo(i -> i.supportedCapabilities(supportedUsbCapabilities))
            .getSupportedCapabilities(Transport.USB));

    Map<Transport, Integer> supportedNfcCapabilities = new HashMap<>();
    supportedNfcCapabilities.put(Transport.NFC, 4096);
    assertEquals(
        0,
        adjustedInfo(i -> i.supportedCapabilities(supportedNfcCapabilities))
            .getSupportedCapabilities(Transport.USB));
    assertEquals(
        4096,
        adjustedInfo(i -> i.supportedCapabilities(supportedNfcCapabilities))
            .getSupportedCapabilities(Transport.NFC));

    Map<Transport, Integer> supportedCapabilities = new HashMap<>();
    supportedCapabilities.put(Transport.NFC, 8192);
    supportedCapabilities.put(Transport.USB, 16384);
    assertEquals(
        16384,
        adjustedInfo(i -> i.supportedCapabilities(supportedCapabilities))
            .getSupportedCapabilities(Transport.USB));
    assertEquals(
        8192,
        adjustedInfo(i -> i.supportedCapabilities(supportedCapabilities))
            .getSupportedCapabilities(Transport.NFC));
  }

  @Test
  public void testEnabledNfcCapabilities() {
    Map<Transport, Integer> supportedCapabilities = new HashMap<>();
    supportedCapabilities.put(Transport.NFC, 8192);
    assertEquals(
        Integer.valueOf(4096),
        adjustedInfo(
                i -> {
                  i.supportedCapabilities(supportedCapabilities);
                  i.config(config(c -> c.enabledCapabilities(Transport.NFC, 4096)));
                })
            .getConfig()
            .getEnabledCapabilities(Transport.NFC));

    // null enabled capabilities
    assertEquals(
        Integer.valueOf(8192),
        adjustedInfo(i -> i.supportedCapabilities(supportedCapabilities))
            .getConfig()
            .getEnabledCapabilities(Transport.NFC));

    List<FormFactor> usbOnlyFactors = new ArrayList<>();
    usbOnlyFactors.add(FormFactor.USB_A_NANO);
    usbOnlyFactors.add(FormFactor.USB_C_NANO);
    usbOnlyFactors.add(FormFactor.USB_C_LIGHTNING);
    usbOnlyFactors.add(FormFactor.USB_C_KEYCHAIN);

    for (FormFactor formFactor : usbOnlyFactors) {

      DeviceInfo info =
          adjustedInfo(
              i -> {
                i.formFactor(formFactor);
                i.supportedCapabilities(supportedCapabilities);
                i.version(new Version(5, 2, 3));
                i.config(config(c -> c.enabledCapabilities(Transport.NFC, 4096)));
              });

      assertNull(info.getConfig().getEnabledCapabilities(Transport.NFC));

      assertEquals(0, info.getSupportedCapabilities(Transport.NFC));

      if (formFactor == FormFactor.USB_C_KEYCHAIN) {
        info =
            adjustedInfo(
                i -> {
                  i.formFactor(formFactor);
                  i.supportedCapabilities(supportedCapabilities);
                  i.version(new Version(5, 2, 4));
                  i.config(config(c -> c.enabledCapabilities(Transport.NFC, 4096)));
                });

        assertEquals(Integer.valueOf(4096), info.getConfig().getEnabledCapabilities(Transport.NFC));

        assertEquals(8192, info.getSupportedCapabilities(Transport.NFC));

        // null enabled capabilities
        info =
            adjustedInfo(
                i -> {
                  i.formFactor(formFactor);
                  i.supportedCapabilities(supportedCapabilities);
                  i.version(new Version(5, 2, 4));
                });

        assertEquals(Integer.valueOf(8192), info.getConfig().getEnabledCapabilities(Transport.NFC));

        assertEquals(8192, info.getSupportedCapabilities(Transport.NFC));
      }
    }
  }

  @Test
  public void testEnabledUsbCapabilities() {
    Map<Transport, Integer> supportedCapabilities = new HashMap<>();
    supportedCapabilities.put(Transport.USB, 0b0111);

    // enabled usb capabilities are not null
    DeviceInfo info =
        adjustedInfo(
            i -> {
              i.supportedCapabilities(supportedCapabilities);
              i.config(config(c -> c.enabledCapabilities(Transport.USB, 0b1011)));
            });

    assertEquals(Integer.valueOf(0b1011), info.getConfig().getEnabledCapabilities(Transport.USB));

    assertEquals(0b0111, info.getSupportedCapabilities(Transport.USB));

    // no usb transport support
    // enabled usb capabilities are not null
    info = adjustedInfo(i -> i.config(config(c -> c.enabledCapabilities(Transport.USB, 0b1011))));

    assertEquals(Integer.valueOf(0b1011), info.getConfig().getEnabledCapabilities(Transport.USB));

    assertEquals(0, info.getSupportedCapabilities(Transport.USB));

    // null enabled capabilities
    info = adjustedInfo(i -> i.supportedCapabilities(supportedCapabilities));

    assertEquals(Integer.valueOf(0b0111), info.getConfig().getEnabledCapabilities(Transport.USB));

    assertEquals(0b0011, info.getSupportedCapabilities(Transport.USB));

    // with OTP interface
    info = adjustedInfo(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0111);

    assertEquals(Integer.valueOf(0b0111), info.getConfig().getEnabledCapabilities(Transport.USB));

    assertEquals(0b0011, info.getSupportedCapabilities(Transport.USB));

    // without OTP interface
    info = adjustedInfo(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0110);

    assertEquals(Integer.valueOf(0b0110), info.getConfig().getEnabledCapabilities(Transport.USB));

    assertEquals(0b0011, info.getSupportedCapabilities(Transport.USB));

    // add FIDO2 capability
    supportedCapabilities.put(Transport.USB, 0x207);
    // with FIDO interface
    info = adjustedInfo(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0111);

    assertEquals(Integer.valueOf(0x207), info.getConfig().getEnabledCapabilities(Transport.USB));

    assertEquals(0x207, info.getSupportedCapabilities(Transport.USB));

    // without FIDO interface
    supportedCapabilities.put(Transport.USB, 0x207);
    info = adjustedInfo(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0101);

    assertEquals(Integer.valueOf(0x5), info.getConfig().getEnabledCapabilities(Transport.USB));

    assertEquals(0x207, info.getSupportedCapabilities(Transport.USB));

    // all CCID capabilities (and FIDO2+U2F)
    supportedCapabilities.put(Transport.USB, 0x23A);
    // with CCID interface
    info = adjustedInfo(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0111);

    assertEquals(Integer.valueOf(0x23A), info.getConfig().getEnabledCapabilities(Transport.USB));

    assertEquals(0x23A, info.getSupportedCapabilities(Transport.USB));

    // without FIDO interface
    supportedCapabilities.put(Transport.USB, 0x23A);
    info = adjustedInfo(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0011);

    assertEquals(Integer.valueOf(0x202), info.getConfig().getEnabledCapabilities(Transport.USB));

    assertEquals(0x23A, info.getSupportedCapabilities(Transport.USB));
  }

  DeviceInfo adjustedInfo(TestUtil.DeviceInfoBuilder infoBuilder) {
    YubiKeyType yubiKeyType = YubiKeyType.YK4;
    int interfaces = UsbInterface.CCID | UsbInterface.OTP | UsbInterface.FIDO;

    return adjustedInfo(infoBuilder, yubiKeyType, interfaces);
  }

  // call the function under test DeviceUtil.adjustDeviceInfo
  DeviceInfo adjustedInfo(
      TestUtil.DeviceInfoBuilder infoBuilder, @Nullable YubiKeyType keyType, int interfaces) {
    DeviceInfo.Builder builder = new DeviceInfo.Builder();
    infoBuilder.createWith(builder);
    return DeviceUtil.adjustDeviceInfo(builder.build(), keyType, interfaces);
  }
}

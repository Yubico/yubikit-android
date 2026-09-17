/*
 * Copyright (C) 2024-2026 Yubico.
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

import static com.yubico.yubikit.management.FormFactor.UNKNOWN;
import static com.yubico.yubikit.management.FormFactor.USB_A_BIO;
import static com.yubico.yubikit.management.FormFactor.USB_A_KEYCHAIN;
import static com.yubico.yubikit.management.FormFactor.USB_A_NANO;
import static com.yubico.yubikit.management.FormFactor.USB_C_BIO;
import static com.yubico.yubikit.management.FormFactor.USB_C_KEYCHAIN;
import static com.yubico.yubikit.management.FormFactor.USB_C_LIGHTNING;
import static com.yubico.yubikit.management.FormFactor.USB_C_NANO;
import static com.yubico.yubikit.support.TestUtil.info;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbInterface;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.YubiKeyType;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.FormFactor;
import java.util.EnumMap;
import java.util.Map;
import org.junit.Test;

public class GetNameTest {

  // ---- assertion helpers ----

  private static void assertName(
      String expected, FormFactor ff, Version v, Map<Transport, Integer> caps, YubiKeyType type) {
    assertEquals(
        expected,
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(ff);
                  if (v != null) i.version(v);
                  i.supportedCapabilities(caps);
                }),
            type));
  }

  private static void assertName(
      String expected, FormFactor ff, Version v, Map<Transport, Integer> caps) {
    assertName(expected, ff, v, caps, YubiKeyType.YK4);
  }

  // ---- capability map helpers ----

  static Map<Transport, Integer> usbOnly(int bits) {
    Map<Transport, Integer> m = new EnumMap<>(Transport.class);
    m.put(Transport.USB, bits);
    return m;
  }

  static Map<Transport, Integer> usbAndNfc(int bits) {
    Map<Transport, Integer> m = new EnumMap<>(Transport.class);
    m.put(Transport.USB, bits);
    m.put(Transport.NFC, bits);
    return m;
  }

  // ---- capability bit constants ----

  static final int fidoBits = Capability.FIDO2.bit | Capability.U2F.bit;
  static final int yk5UsbBits =
      fidoBits
          | Capability.OATH.bit
          | Capability.PIV.bit
          | Capability.OPENPGP.bit
          | Capability.OTP.bit;
  static final int yk4Bits =
      Capability.U2F.bit
          | Capability.OATH.bit
          | Capability.PIV.bit
          | Capability.OPENPGP.bit
          | Capability.OTP.bit;

  // ---- pre-built capability maps ----

  static final Map<Transport, Integer> fidoCapabilities = usbAndNfc(fidoBits);
  static final Map<Transport, Integer> bioCapabilities = usbOnly(fidoBits);
  static final Map<Transport, Integer> bioCcidCapabilities = usbOnly(fidoBits | UsbInterface.CCID);
  static final Map<Transport, Integer> bioMultiProtocolCapabilities =
      usbOnly(fidoBits | Capability.PIV.bit);
  static final Map<Transport, Integer> yk5UsbOnlyCapabilities = usbOnly(yk5UsbBits);
  static final Map<Transport, Integer> yk5Capabilities = usbAndNfc(yk5UsbBits);
  static final Map<Transport, Integer> yk4Capabilities = usbAndNfc(yk4Bits);
  static final Map<Transport, Integer> edgeCapabilities =
      usbOnly(Capability.U2F.bit | Capability.OTP.bit);

  // ---- tests ----

  @Test
  public void testYubiKeyUnknownFormFactor() {
    assertName("YubiKey 5", UNKNOWN, new Version(5, 4, 3), yk5UsbOnlyCapabilities);
    assertName("YubiKey 5 NFC", UNKNOWN, new Version(5, 4, 3), yk5Capabilities);
  }

  @Test
  public void testYubiKey5() {
    assertName("YubiKey 5A", USB_A_KEYCHAIN, new Version(5, 4, 3), yk5UsbOnlyCapabilities);
    assertName("YubiKey 5C", USB_C_KEYCHAIN, new Version(5, 4, 3), yk5UsbOnlyCapabilities);
  }

  @Test
  public void testYubiKey5Nfc() {
    assertName("YubiKey 5 NFC", USB_A_KEYCHAIN, new Version(5, 4, 3), yk5Capabilities);
    assertName("YubiKey 5C NFC", USB_C_KEYCHAIN, new Version(5, 4, 3), yk5Capabilities);
  }

  @Test
  public void testYubiKey5Nano() {
    assertName("YubiKey 5 Nano", USB_A_NANO, new Version(5, 4, 3), yk5UsbOnlyCapabilities);
    assertName("YubiKey 5C Nano", USB_C_NANO, new Version(5, 4, 3), yk5UsbOnlyCapabilities);
  }

  @Test
  public void testYubiKey5Lightning() {
    assertName("YubiKey 5Ci", USB_C_LIGHTNING, new Version(5, 4, 3), yk5UsbOnlyCapabilities);
  }

  @Test
  public void testSecurityKey() {
    assertName("FIDO U2F Security Key", USB_A_KEYCHAIN, null, usbOnly(fidoBits), YubiKeyType.SKY);
    assertName(
        "Security Key by Yubico",
        USB_A_KEYCHAIN,
        null,
        usbOnly(Capability.U2F.bit),
        YubiKeyType.SKY);
    assertName("Security Key NFC", USB_A_KEYCHAIN, null, usbAndNfc(fidoBits), YubiKeyType.SKY);

    assertEquals(
        "Security Key NFC",
        DeviceUtil.getName(
            info(
                i -> {
                  i.isSky(true);
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 6, 0));
                  i.supportedCapabilities(fidoCapabilities);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "Security Key C NFC",
        DeviceUtil.getName(
            info(
                i -> {
                  i.isSky(true);
                  i.formFactor(USB_C_KEYCHAIN);
                  i.version(new Version(5, 6, 0));
                  i.supportedCapabilities(fidoCapabilities);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "Security Key NFC",
        DeviceUtil.getName(
            info(
                i -> {
                  i.version(new Version(3, 2, 0));
                  i.supportedCapabilities(fidoCapabilities);
                }),
            null));
  }

  @Test
  public void testFips() {
    assertEquals(
        "YubiKey 5 NFC FIPS",
        DeviceUtil.getName(
            info(
                i -> {
                  i.isFips(true);
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 6, 0));
                  i.supportedCapabilities(yk5Capabilities);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey 5C NFC FIPS",
        DeviceUtil.getName(
            info(
                i -> {
                  i.isFips(true);
                  i.formFactor(USB_C_KEYCHAIN);
                  i.version(new Version(5, 6, 0));
                  i.supportedCapabilities(yk5Capabilities);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey 5A FIPS",
        DeviceUtil.getName(
            info(
                i -> {
                  i.isFips(true);
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 6, 0));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey 5C FIPS",
        DeviceUtil.getName(
            info(
                i -> {
                  i.isFips(true);
                  i.formFactor(USB_C_KEYCHAIN);
                  i.version(new Version(5, 6, 0));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testYubiKey4Fips() {
    assertEquals(
        "YubiKey FIPS",
        DeviceUtil.getName(
            info(
                i -> {
                  i.isFips(true);
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(4, 0, 0));
                  i.supportedCapabilities(yk4Capabilities);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testYubiKeyEdge() {
    assertName("YubiKey Edge", USB_A_KEYCHAIN, new Version(4, 0, 0), edgeCapabilities);
  }

  @Test
  public void testYubiKey4() {
    assertName("YubiKey 4", USB_A_KEYCHAIN, new Version(4, 0, 0), yk4Capabilities);

    assertEquals(
        "YubiKey 4",
        DeviceUtil.getName(
            info(
                i -> {
                  i.version(new Version(4, 2, 0));
                  i.supportedCapabilities(yk4Capabilities);
                }),
            null));
  }

  @Test
  public void testBioSeriesFidoEdition() {
    assertName("YubiKey Bio - FIDO Edition", USB_A_BIO, new Version(5, 6, 6), bioCcidCapabilities);
    assertName(
        "YubiKey C Bio - FIDO Edition", USB_C_BIO, new Version(5, 6, 6), bioCcidCapabilities);
    assertName("YubiKey Bio - FIDO Edition", USB_A_BIO, new Version(5, 6, 6), bioCapabilities);
    assertName("YubiKey C Bio - FIDO Edition", USB_C_BIO, new Version(5, 6, 6), bioCapabilities);
  }

  @Test
  public void testBioSeriesMultiProtocolEdition() {
    // multi-protocol has PIV and a serial number
    assertEquals(
        "YubiKey Bio - Multi-protocol Edition",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_BIO);
                  i.version(new Version(5, 6, 6));
                  i.supportedCapabilities(bioMultiProtocolCapabilities);
                  i.serialNumber(12345);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey C Bio - Multi-protocol Edition",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_C_BIO);
                  i.version(new Version(5, 6, 6));
                  i.supportedCapabilities(bioMultiProtocolCapabilities);
                  i.serialNumber(12345);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testSecurityKeyEnterpriseEdition() {
    assertEquals(
        "Security Key NFC - Enterprise Edition",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 4, 3));
                  i.isSky(true);
                  i.supportedCapabilities(fidoCapabilities);
                  i.serialNumber(65454545);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "Security Key C NFC - Enterprise Edition",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_C_KEYCHAIN);
                  i.version(new Version(5, 4, 3));
                  i.isSky(true);
                  i.supportedCapabilities(fidoCapabilities);
                  i.serialNumber(65454545);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testEnhancedPin() {
    assertEquals(
        "YubiKey 5 NFC - Enhanced PIN",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 4, 3));
                  i.pinComplexity(true);
                  i.supportedCapabilities(fidoCapabilities);
                  i.serialNumber(65454545);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey 5C NFC - Enhanced PIN",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_C_KEYCHAIN);
                  i.version(new Version(5, 4, 3));
                  i.pinComplexity(true);
                  i.supportedCapabilities(fidoCapabilities);
                  i.serialNumber(65454545);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testYubiKeyPreview() {
    assertName("YubiKey Preview", USB_A_KEYCHAIN, new Version(5, 0, 0), yk5UsbOnlyCapabilities);
    assertName("YubiKey Preview", USB_A_KEYCHAIN, new Version(5, 0, 10), yk5UsbOnlyCapabilities);
    assertNotEquals(
        "YubiKey Preview",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 1, 0));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));

    assertName("YubiKey Preview", USB_A_KEYCHAIN, new Version(5, 2, 2), yk5UsbOnlyCapabilities);
    assertNotEquals(
        "YubiKey Preview",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 2, 3));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));

    assertName("YubiKey Preview", USB_A_KEYCHAIN, new Version(5, 5, 1), yk5UsbOnlyCapabilities);
    assertNotEquals(
        "YubiKey Preview",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 5, 3));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testYubiKeyNeo() {
    assertEquals("YubiKey NEO", DeviceUtil.getName(info(i -> {}), YubiKeyType.NEO));

    assertEquals(
        "YubiKey NEO",
        DeviceUtil.getName(
            info(
                i -> {
                  i.serialNumber(1234343);
                  i.version(new Version(3, 2, 0));
                }),
            null));
  }

  @Test
  public void testLegacyKeys() {
    assertEquals("YubiKey Standard", DeviceUtil.getName(info(i -> {}), YubiKeyType.YKS));
    assertEquals("YubiKey Plus", DeviceUtil.getName(info(i -> {}), YubiKeyType.YKP));
    assertEquals(
        "YubiKey (0.3.2)",
        DeviceUtil.getName(info(i -> i.version(new Version(0, 3, 2))), YubiKeyType.YK4));
    assertEquals(
        "YubiKey", DeviceUtil.getName(info(i -> i.version(new Version(3, 3, 2))), YubiKeyType.YK4));
  }

  @Test
  public void testFidoCcid() {
    // FIDO_CCID is a transport flag (firmware 5.8+) and must not affect the product name.
    int yk5UsbBitsWithFidoCcid = yk5UsbBits | Capability.FIDO_CCID.bit;
    int fidoBitsWithFidoCcid = fidoBits | Capability.FIDO_CCID.bit;

    assertName("YubiKey 5A", USB_A_KEYCHAIN, new Version(5, 8, 0), usbOnly(yk5UsbBitsWithFidoCcid));
    assertName("YubiKey 5C", USB_C_KEYCHAIN, new Version(5, 8, 0), usbOnly(yk5UsbBitsWithFidoCcid));
    assertName(
        "YubiKey 5 NFC", USB_A_KEYCHAIN, new Version(5, 8, 0), usbAndNfc(yk5UsbBitsWithFidoCcid));
    assertName(
        "YubiKey 5C NFC", USB_C_KEYCHAIN, new Version(5, 8, 0), usbAndNfc(yk5UsbBitsWithFidoCcid));

    // Security Key variants
    assertName(
        "Security Key NFC", USB_A_KEYCHAIN, null, usbAndNfc(fidoBitsWithFidoCcid), YubiKeyType.SKY);

    // Bio FIDO Edition
    assertName(
        "YubiKey Bio - FIDO Edition",
        USB_A_BIO,
        new Version(5, 8, 0),
        usbOnly(fidoBitsWithFidoCcid));
    assertName(
        "YubiKey C Bio - FIDO Edition",
        USB_C_BIO,
        new Version(5, 8, 0),
        usbOnly(fidoBitsWithFidoCcid));
  }
}

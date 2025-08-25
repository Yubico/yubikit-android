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
import java.util.HashMap;
import org.junit.Test;

public class GetNameTest {
  @Test
  public void testYubiKeyUnknownFormFactor() {
    assertEquals(
        "YubiKey 5",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(UNKNOWN);
                  i.version(new Version(5, 4, 3));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey 5 NFC",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(UNKNOWN);
                  i.version(new Version(5, 4, 3));
                  i.supportedCapabilities(yk5Capabilities);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testYubiKey5() {
    assertEquals(
        "YubiKey 5A",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 4, 3));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey 5C",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_C_KEYCHAIN);
                  i.version(new Version(5, 4, 3));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testYubiKey5Nfc() {
    assertEquals(
        "YubiKey 5 NFC",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 4, 3));
                  i.supportedCapabilities(yk5Capabilities);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey 5C NFC",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_C_KEYCHAIN);
                  i.version(new Version(5, 4, 3));
                  i.supportedCapabilities(yk5Capabilities);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testYubiKey5Nano() {
    assertEquals(
        "YubiKey 5 Nano",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_NANO);
                  i.version(new Version(5, 4, 3));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey 5C Nano",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_C_NANO);
                  i.version(new Version(5, 4, 3));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testYubiKey5Lightning() {
    assertEquals(
        "YubiKey 5Ci",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_C_LIGHTNING);
                  i.version(new Version(5, 4, 3));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testSecurityKey() {

    assertEquals(
        "FIDO U2F Security Key",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.supportedCapabilities(
                      new HashMap<Transport, Integer>() {
                        {
                          put(Transport.USB, fidoBits);
                        }
                      });
                }),
            YubiKeyType.SKY));

    assertEquals(
        "Security Key by Yubico",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.supportedCapabilities(
                      new HashMap<Transport, Integer>() {
                        {
                          put(Transport.USB, Capability.U2F.bit);
                        }
                      });
                }),
            YubiKeyType.SKY));

    assertEquals(
        "Security Key NFC",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.supportedCapabilities(
                      new HashMap<Transport, Integer>() {
                        {
                          put(Transport.NFC, fidoBits);
                        }
                      });
                }),
            YubiKeyType.SKY));

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
    assertEquals(
        "YubiKey Edge",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(4, 0, 0));
                  i.supportedCapabilities(edgeCapabilities);
                }),
            YubiKeyType.YK4));
  }

  @Test
  public void testYubiKey4() {
    assertEquals(
        "YubiKey 4",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(4, 0, 0));
                  i.supportedCapabilities(yk4Capabilities);
                }),
            YubiKeyType.YK4));

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
    assertEquals(
        "YubiKey Bio - FIDO Edition",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_BIO);
                  i.version(new Version(5, 6, 6));
                  i.supportedCapabilities(bioCapabilities);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey C Bio - FIDO Edition",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_C_BIO);
                  i.version(new Version(5, 6, 6));
                  i.supportedCapabilities(bioCapabilities);
                }),
            YubiKeyType.YK4));
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
  public void testBioSeries() {
    // these are neither Enterprise nor Multi-protocol Edition Bios
    assertEquals(
        "YubiKey Bio",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_BIO);
                  i.version(new Version(5, 6, 6));
                  i.supportedCapabilities(
                      new HashMap<Transport, Integer>() {
                        {
                          put(Transport.USB, fidoBits | UsbInterface.CCID);
                        }
                      });
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey C Bio",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_C_BIO);
                  i.version(new Version(5, 6, 6));
                  i.supportedCapabilities(
                      new HashMap<Transport, Integer>() {
                        {
                          put(Transport.USB, fidoBits | UsbInterface.CCID);
                        }
                      });
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
    assertEquals(
        "YubiKey Preview",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 0, 0));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey Preview",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 0, 10));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));

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

    assertEquals(
        "YubiKey Preview",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 2, 2));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));

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

    assertEquals(
        "YubiKey Preview",
        DeviceUtil.getName(
            info(
                i -> {
                  i.formFactor(USB_A_KEYCHAIN);
                  i.version(new Version(5, 5, 1));
                  i.supportedCapabilities(yk5UsbOnlyCapabilities);
                }),
            YubiKeyType.YK4));

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

    // NEO always has a serial number
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
        DeviceUtil.getName(
            info(
                i -> {
                  i.version(new Version(0, 3, 2));
                }),
            YubiKeyType.YK4));

    assertEquals(
        "YubiKey",
        DeviceUtil.getName(
            info(
                i -> {
                  i.version(new Version(3, 3, 2));
                }),
            YubiKeyType.YK4));
  }

  static final int fidoBits = Capability.FIDO2.bit | Capability.U2F.bit;
  static final HashMap<Transport, Integer> fidoCapabilities =
      new HashMap<Transport, Integer>() {
        {
          put(Transport.USB, fidoBits);
          put(Transport.NFC, fidoBits);
        }
      };

  static final HashMap<Transport, Integer> bioCapabilities =
      new HashMap<Transport, Integer>() {
        {
          put(Transport.USB, fidoBits);
        }
      };

  static final HashMap<Transport, Integer> bioMultiProtocolCapabilities =
      new HashMap<Transport, Integer>() {
        {
          put(Transport.USB, fidoBits | Capability.PIV.bit);
        }
      };

  static final HashMap<Transport, Integer> yk5UsbOnlyCapabilities =
      new HashMap<Transport, Integer>() {
        {
          put(
              Transport.USB,
              fidoBits
                  | Capability.OATH.bit
                  | Capability.PIV.bit
                  | Capability.OPENPGP.bit
                  | Capability.OTP.bit);
        }
      };

  static final HashMap<Transport, Integer> yk5Capabilities =
      new HashMap<Transport, Integer>() {
        {
          int capabilities =
              fidoBits
                  | Capability.OATH.bit
                  | Capability.PIV.bit
                  | Capability.OPENPGP.bit
                  | Capability.OTP.bit;
          put(Transport.USB, capabilities);
          put(Transport.NFC, capabilities);
        }
      };

  static final HashMap<Transport, Integer> yk4Capabilities =
      new HashMap<Transport, Integer>() {
        {
          int capabilities =
              Capability.U2F.bit
                  | Capability.OATH.bit
                  | Capability.PIV.bit
                  | Capability.OPENPGP.bit
                  | Capability.OTP.bit;
          put(Transport.USB, capabilities);
          put(Transport.NFC, capabilities);
        }
      };

  static final HashMap<Transport, Integer> edgeCapabilities =
      new HashMap<Transport, Integer>() {
        {
          int capabilities = Capability.U2F.bit | Capability.OTP.bit;
          put(Transport.USB, capabilities);
        }
      };
}

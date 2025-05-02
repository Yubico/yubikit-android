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

import static com.yubico.yubikit.management.Capability.FIDO2;
import static com.yubico.yubikit.management.Capability.HSMAUTH;
import static com.yubico.yubikit.management.Capability.OATH;
import static com.yubico.yubikit.management.Capability.OPENPGP;
import static com.yubico.yubikit.management.Capability.PIV;
import static com.yubico.yubikit.management.TestUtil.defaultVersion;
import static com.yubico.yubikit.management.TestUtil.emptyTlvs;
import static com.yubico.yubikit.management.TestUtil.tlvs;
import static com.yubico.yubikit.testing.Codec.fromHex;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.Version;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Test;

public class DeviceInfoTest {

  @Test
  public void testParseSerialNumber() {
    assertNull(defaultInfo().getSerialNumber());
    assertEquals(Integer.valueOf(123456789), infoOf(0x02, fromHex("075BCD15")).getSerialNumber());
  }

  @Test
  public void testParseVersion() {
    assertEquals(new Version(5, 3, 4), infoOf(0x05, fromHex("050304")).getVersion());
  }

  @Test
  public void testUseDefaultVersion() {
    assertEquals(defaultVersion, defaultInfo().getVersion());
  }

  @Test
  public void testParseFormFactor() {
    assertEquals(FormFactor.UNKNOWN, defaultInfo().getFormFactor());
    assertEquals(FormFactor.USB_A_KEYCHAIN, infoOf(0x04, fromHex("01")).getFormFactor());
    assertEquals(FormFactor.USB_A_NANO, infoOf(0x04, fromHex("02")).getFormFactor());
    assertEquals(FormFactor.USB_C_KEYCHAIN, infoOf(0x04, fromHex("03")).getFormFactor());
    assertEquals(FormFactor.USB_C_NANO, infoOf(0x04, fromHex("04")).getFormFactor());
    assertEquals(FormFactor.USB_C_LIGHTNING, infoOf(0x04, fromHex("05")).getFormFactor());
    assertEquals(FormFactor.USB_A_BIO, infoOf(0x04, fromHex("06")).getFormFactor());
    assertEquals(FormFactor.USB_C_BIO, infoOf(0x04, fromHex("07")).getFormFactor());
    // the form factor byte contains fips (0x80) and sky (0x40) flags
    assertEquals(FormFactor.USB_A_BIO, infoOf(0x04, fromHex("46")).getFormFactor());
    assertEquals(FormFactor.USB_C_NANO, infoOf(0x04, fromHex("84")).getFormFactor());
  }

  @Test
  public void testParseLocked() {
    assertFalse(defaultInfo().isLocked());
    assertTrue(infoOf(0x0a, fromHex("01")).isLocked());
    assertFalse(infoOf(0x0a, fromHex("00")).isLocked());
  }

  @Test
  public void testParseFips() {
    assertFalse(defaultInfo().isFips());
    assertTrue(infoOf(0x04, fromHex("80")).isFips());
    assertTrue(infoOf(0x04, fromHex("C0")).isFips());
    assertFalse(infoOf(0x04, fromHex("40")).isFips());
  }

  @Test
  public void testParseSky() {
    assertFalse(defaultInfo().isSky());
    assertTrue(infoOf(0x04, fromHex("40")).isSky());
    assertTrue(infoOf(0x04, fromHex("C0")).isSky());
    assertFalse(infoOf(0x04, fromHex("80")).isSky());
  }

  @Test
  public void testParsePartNumber() {
    // valid UTF-8
    assertNull(defaultInfo().getPartNumber());
    assertEquals("", infoOf(0x13, new byte[0]).getPartNumber());
    assertEquals(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_=+-",
        infoOf(
                0x13,
                fromHex(
                    "6162636465666768696A6B6C6D6E6F707172737475767778797A41"
                        + "42434445464748494A4B4C4D4E4F505152535455565758595A303132333435363738395"
                        + "F3D2B2D"))
            .getPartNumber());
    assertEquals(
        "ÖÄÅöäåěščřžýáíúůĚŠČŘŽÝÁÍÚŮ",
        infoOf(
                0x13,
                fromHex(
                    "C396C384C385C3B6C3A4C3A5C49BC5A1C48DC599C5BEC3BDC3A1C3"
                        + "ADC3BAC5AFC49AC5A0C48CC598C5BDC39DC381C38DC39AC5AE"))
            .getPartNumber());
    assertEquals("😀", infoOf(0x13, fromHex("F09F9880")).getPartNumber());
    assertEquals(
        "0123456789ABCDEF",
        infoOf(0x13, fromHex("30313233343536373839414243444546")).getPartNumber());

    // invalid UTF-8
    assertNull(infoOf(0x13, fromHex("c328")).getPartNumber());
    assertNull(infoOf(0x13, fromHex("a0a1")).getPartNumber());
    assertNull(infoOf(0x13, fromHex("e228a1")).getPartNumber());
    assertNull(infoOf(0x13, fromHex("e28228")).getPartNumber());
    assertNull(infoOf(0x13, fromHex("f0288cbc")).getPartNumber());
    assertNull(infoOf(0x13, fromHex("f09028bc")).getPartNumber());
    assertNull(infoOf(0x13, fromHex("f0288c28")).getPartNumber());
  }

  @Test
  public void testParseFipsCapable() {
    assertEquals(0, defaultInfo().getFipsCapable());
    assertEquals(FIDO2.bit, infoOf(0x14, fromHex("0001")).getFipsCapable());
    assertEquals(PIV.bit, infoOf(0x14, fromHex("0002")).getFipsCapable());
    assertEquals(OPENPGP.bit, infoOf(0x14, fromHex("0004")).getFipsCapable());
    assertEquals(OATH.bit, infoOf(0x14, fromHex("0008")).getFipsCapable());
    assertEquals(HSMAUTH.bit, infoOf(0x14, fromHex("0010")).getFipsCapable());
    assertEquals(PIV.bit | OATH.bit, infoOf(0x14, fromHex("000A")).getFipsCapable());
  }

  @Test
  public void testParseFipsApproved() {
    assertEquals(0, defaultInfo().getFipsApproved());
    assertEquals(FIDO2.bit, infoOf(0x15, fromHex("0001")).getFipsApproved());
    assertEquals(PIV.bit, infoOf(0x15, fromHex("0002")).getFipsApproved());
    assertEquals(OPENPGP.bit, infoOf(0x15, fromHex("0004")).getFipsApproved());
    assertEquals(OATH.bit, infoOf(0x15, fromHex("0008")).getFipsApproved());
    assertEquals(HSMAUTH.bit, infoOf(0x15, fromHex("0010")).getFipsApproved());
    assertEquals(PIV.bit | OATH.bit, infoOf(0x15, fromHex("000A")).getFipsApproved());
  }

  @Test
  public void testParsePinComplexity() {
    assertFalse(defaultInfo().getPinComplexity());
    assertFalse(infoOf(0x16, fromHex("00")).getPinComplexity());
    assertTrue(infoOf(0x16, fromHex("01")).getPinComplexity());
  }

  @Test
  public void testParseResetBlocked() {
    assertEquals(0, defaultInfo().getResetBlocked());
    assertEquals(1056, infoOf(0x18, fromHex("0420")).getResetBlocked());
  }

  @Test
  public void testParseFpsVersion() {
    assertNull(defaultInfo().getFpsVersion());
    assertNull(infoOf(0x20, fromHex("000000")).getFpsVersion());
    assertNull(infoOf(0x20, fromHex("000000000000000000")).getFpsVersion());
    assertEquals(new Version(0, 0, 1), infoOf(0x20, fromHex("000001")).getFpsVersion());
    assertEquals(new Version(5, 6, 6), infoOf(0x20, fromHex("050606")).getFpsVersion());
  }

  @Test
  public void testParseStmVersion() {
    assertNull(defaultInfo().getStmVersion());
    assertNull(infoOf(0x21, fromHex("000000")).getStmVersion());
    assertNull(infoOf(0x21, fromHex("000000000000000000")).getStmVersion());
    assertEquals(new Version(0, 0, 1), infoOf(0x21, fromHex("000001")).getStmVersion());
    assertEquals(new Version(7, 0, 5), infoOf(0x21, fromHex("070005")).getStmVersion());
  }

  @Test
  public void testParseVersionQualifier() {
    // default version and qualifier
    DeviceInfo info = infoOfVersion(null, null);
    assertEquals(defaultVersion, info.getVersion());
    assertEquals(
        new VersionQualifier(defaultVersion, VersionQualifier.Type.FINAL, 0),
        info.getVersionQualifier());
    assertEquals("2.2.2", info.getVersionName());

    // no qualifier provided
    info = infoOfVersion(fromHex("030403"), null);
    assertEquals(new Version(3, 4, 3), info.getVersion());
    // default qualifier with provided version
    assertEquals(
        new VersionQualifier(new Version(3, 4, 3), VersionQualifier.Type.FINAL, 0),
        info.getVersionQualifier());
    assertEquals("3.4.3", info.getVersionName());

    // ALPHA version qualifier
    info = infoOfVersion(fromHex("000001"), fromHex("0103050403020100030400000000"));
    assertEquals(new Version(5, 4, 3), info.getVersion());
    assertEquals("5.4.3.alpha.0", info.getVersionQualifier().toString());
    assertEquals("5.4.3.alpha.0", info.getVersionName());

    // BETA version qualifier
    info = infoOfVersion(fromHex("000001"), fromHex("01030507080201010304000000e9"));
    assertEquals(new Version(5, 7, 8), info.getVersion());
    assertEquals("5.7.8.beta.233", info.getVersionQualifier().toString());
    assertEquals("5.7.8.beta.233", info.getVersionName());

    // FINAL version qualifier
    info = infoOfVersion(fromHex("050404"), fromHex("0103050404020102030400000005"));
    assertEquals(new Version(5, 4, 4), info.getVersion());
    assertEquals("5.4.4.final.5", info.getVersionQualifier().toString());
    assertEquals("5.4.4", info.getVersionName());

    info = infoOfVersion(fromHex("050709"), fromHex("01030507090201020304FFFFFFFF"));
    assertEquals(new Version(5, 7, 9), info.getVersion());
    assertEquals("5.7.9.final.4294967295", info.getVersionQualifier().toString());
    assertEquals("5.7.9", info.getVersionName());

    info = infoOfVersion(fromHex("05070A"), fromHex("010305070A020102030480000000"));
    assertEquals(new Version(5, 7, 10), info.getVersion());
    assertEquals("5.7.10.final.2147483648", info.getVersionQualifier().toString());
    assertEquals("5.7.10", info.getVersionName());

    info = infoOfVersion(fromHex("05070B"), fromHex("010305070B02010203047FFFFFFF"));
    assertEquals(new Version(5, 7, 11), info.getVersion());
    assertEquals("5.7.11.final.2147483647", info.getVersionQualifier().toString());
    assertEquals("5.7.11", info.getVersionName());
  }

  private DeviceInfo defaultInfo() {
    return DeviceInfo.parseTlvs(emptyTlvs(), defaultVersion);
  }

  private DeviceInfo infoOf(int tag, byte[] data) {
    return DeviceInfo.parseTlvs(tlvs(tag, data), defaultVersion);
  }

  // builds a DeviceInfo object from the given version and version qualifier bytes
  private DeviceInfo infoOfVersion(
      @Nullable byte[] versionBytes, @Nullable byte[] versionQualifierBytes) {

    Map<Integer, byte[]> tlvs = new HashMap<>();
    if (versionBytes != null) {
      tlvs.put(0x05, versionBytes);
    }
    if (versionQualifierBytes != null) {
      tlvs.put(0x19, versionQualifierBytes);
    }

    return DeviceInfo.parseTlvs(tlvs, defaultVersion);
  }
}

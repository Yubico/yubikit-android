/*
 * Copyright (C) 2022,2024 Yubico.
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.smartcard.AppId;
import org.junit.Test;

public class DeviceUtilTest {
  @Test
  public void ccidAppletTest() {
    assertArrayEquals(AppId.OPENPGP, DeviceUtil.CcidApplet.OPENPGP.aid);
    assertArrayEquals(AppId.OATH, DeviceUtil.CcidApplet.OATH.aid);
    assertArrayEquals(AppId.PIV, DeviceUtil.CcidApplet.PIV.aid);
    assertArrayEquals(AppId.FIDO, DeviceUtil.CcidApplet.FIDO.aid);
    assertArrayEquals(
        new byte[] {(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x10, 0x02},
        DeviceUtil.CcidApplet.AID_U2F_YUBICO.aid);
  }

  @Test
  public void otpDataTest() {
    assertEquals(new Version(1, 2, 3), new DeviceUtil.OtpData(new Version(1, 2, 3), null).version);
    assertNull(new DeviceUtil.OtpData(new Version(1, 2, 3), null).serial);
    assertEquals(Integer.valueOf(123), new DeviceUtil.OtpData(new Version(1, 2, 3), 123).serial);
  }
}

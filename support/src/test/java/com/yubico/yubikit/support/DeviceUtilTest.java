/*
 * Copyright (C) 2022 Yubico.
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

import static com.yubico.yubikit.support.Util.info;
import static com.yubico.yubikit.support.Util.infoNfc;
import static com.yubico.yubikit.support.Util.infoSky;
import static com.yubico.yubikit.support.Util.infoSkyEnterprise;

import com.yubico.yubikit.core.YubiKeyType;
import com.yubico.yubikit.management.FormFactor;

import org.junit.Assert;
import org.junit.Test;

public class DeviceUtilTest {

    YubiKeyType keyType = YubiKeyType.YK4;

    @Test
    public void getYubiKeyName() {
        Assert.assertEquals("YubiKey 5A", DeviceUtil.getName(info(FormFactor.USB_A_KEYCHAIN), keyType));
        Assert.assertEquals("YubiKey 5 NFC", DeviceUtil.getName(infoNfc(FormFactor.USB_A_KEYCHAIN), keyType));
        Assert.assertEquals("YubiKey 5 Nano", DeviceUtil.getName(info(FormFactor.USB_A_NANO), keyType));
        Assert.assertEquals("YubiKey 5C", DeviceUtil.getName(info(FormFactor.USB_C_KEYCHAIN), keyType));
        Assert.assertEquals("YubiKey 5C NFC", DeviceUtil.getName(infoNfc(FormFactor.USB_C_KEYCHAIN), keyType));
        Assert.assertEquals("YubiKey 5C Nano", DeviceUtil.getName(info(FormFactor.USB_C_NANO), keyType));
        Assert.assertEquals("YubiKey 5Ci", DeviceUtil.getName(info(FormFactor.USB_C_LIGHTNING), keyType));
        Assert.assertEquals("YubiKey Bio", DeviceUtil.getName(info(FormFactor.USB_A_BIO), keyType));
        Assert.assertEquals("YubiKey C Bio", DeviceUtil.getName(info(FormFactor.USB_C_BIO), keyType));
        Assert.assertEquals("YubiKey 5", DeviceUtil.getName(info(FormFactor.UNKNOWN), keyType));
        Assert.assertEquals("YubiKey 5 NFC", DeviceUtil.getName(infoNfc(FormFactor.UNKNOWN), keyType));
    }

    @Test
    public void getSecurityKeyName() {
        Assert.assertEquals("Security Key NFC", DeviceUtil.getName(infoSky(FormFactor.USB_A_KEYCHAIN), keyType));
        Assert.assertEquals("Security Key C NFC", DeviceUtil.getName(infoSky(FormFactor.USB_C_KEYCHAIN), keyType));
        Assert.assertEquals("Security Key NFC - Enterprise Edition", DeviceUtil.getName(infoSkyEnterprise(FormFactor.USB_A_KEYCHAIN), keyType));
        Assert.assertEquals("Security Key C NFC - Enterprise Edition", DeviceUtil.getName(infoSkyEnterprise(FormFactor.USB_C_KEYCHAIN), keyType));
        Assert.assertEquals("Security Key NFC Bio - Enterprise Edition", DeviceUtil.getName(infoSkyEnterprise(FormFactor.USB_A_BIO), keyType));
        Assert.assertEquals("Security Key C NFC Bio - Enterprise Edition", DeviceUtil.getName(infoSkyEnterprise(FormFactor.USB_C_BIO), keyType));
    }
}

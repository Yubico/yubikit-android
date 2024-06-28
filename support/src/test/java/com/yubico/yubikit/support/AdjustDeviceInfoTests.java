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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbInterface;
import com.yubico.yubikit.core.YubiKeyType;
import com.yubico.yubikit.management.DeviceConfig;
import com.yubico.yubikit.management.DeviceInfo;

import org.junit.Test;

import javax.annotation.Nullable;

public class AdjustDeviceInfoTests {

    @Test
    public void testConfigDeviceFlags() {
        assertNull(
                info(i -> {
                }).getConfig().getDeviceFlags());

        assertEquals(
                Integer.valueOf(123456),
                info(i -> i.config(config(c -> c.deviceFlags(123456))))
                        .getConfig().getDeviceFlags());
    }

    @Test
    public void testConfigAutoEjectTimeout() {
        assertNull(
                info(i -> {
                }).getConfig().getAutoEjectTimeout());

        assertEquals(
                Short.valueOf((short)13288),
                info(i -> i.config(config(c -> c.autoEjectTimeout((short)13288))))
                        .getConfig().getAutoEjectTimeout());
    }

    @Test
    public void testConfigChallengeResponseTimeout() {
        assertNull(
                info(i -> {
                }).getConfig().getChallengeResponseTimeout());

        assertEquals(
                Byte.valueOf((byte)84),
                info(i -> i.config(config(c -> c.challengeResponseTimeout((byte)84))))
                        .getConfig().getChallengeResponseTimeout());
    }

    @Test
    public void testConfigEnabledCapabilitiesUsb() {
        assertNull(
                info(i -> {
                }).getConfig().getEnabledCapabilities(Transport.USB));

        DeviceInfo info = info(i -> i.config(config(c -> c.enabledCapabilities(Transport.USB, 124))));
        assertEquals(
                Integer.valueOf(124),
                info.getConfig().getEnabledCapabilities(Transport.USB));
        assertNull(
                info.getConfig().getEnabledCapabilities(Transport.NFC));
    }

    @Test
    public void testConfigEnabledCapabilitiesNfc() {
        assertNull(
                info(i -> {
                }).getConfig().getEnabledCapabilities(Transport.NFC));

        DeviceInfo info = info(i -> i.config(config(c -> c.enabledCapabilities(Transport.NFC, 552))));
        assertEquals(
                Integer.valueOf(552),
                info.getConfig().getEnabledCapabilities(Transport.NFC));
        assertNull(
                info.getConfig().getEnabledCapabilities(Transport.USB));
    }

    @Test
    public void testConfigNfcRestricted() {
        assertNull(
                info(i -> {
                }).getConfig().getNfcRestricted());

        assertEquals(
                TRUE,
                info(i -> i.config(config(c -> c.nfcRestricted(true))))
                        .getConfig().getNfcRestricted());

        assertEquals(
                FALSE,
                info(i -> i.config(config(c -> c.nfcRestricted(false))))
                        .getConfig().getNfcRestricted());
    }

    // helper builders
    private interface DeviceConfigBuilder {
        void createWith(DeviceConfig.Builder builder);
    }

    private DeviceConfig config(DeviceConfigBuilder configBuilder) {
        DeviceConfig.Builder builder = new DeviceConfig.Builder();
        configBuilder.createWith(builder);
        return builder.build();
    }

    private interface DeviceInfoBuilder {
        void createWith(DeviceInfo.Builder builder);
    }

    private DeviceInfo info(DeviceInfoBuilder infoBuilder) {
        YubiKeyType yubiKeyType = YubiKeyType.YK4;
        int interfaces = UsbInterface.CCID | UsbInterface.OTP | UsbInterface.FIDO;

        return info(infoBuilder, yubiKeyType, interfaces);
    }

    // this calls the function under test DeviceUtil.fixDeviceInfo
    private DeviceInfo info(
            DeviceInfoBuilder infoBuilder,
            @Nullable YubiKeyType keyType,
            int interfaces) {
        DeviceInfo.Builder builder = new DeviceInfo.Builder();
        infoBuilder.createWith(builder);
        return DeviceUtil.adjustDeviceInfo(builder.build(), keyType, interfaces);
    }
}

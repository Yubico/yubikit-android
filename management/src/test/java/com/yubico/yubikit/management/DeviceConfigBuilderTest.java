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

import static org.junit.Assert.assertEquals;
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
    }

    @Test
    public void testBuild() {
        DeviceConfig defaultConfig = new DeviceConfig.Builder()
                .enabledCapabilities(Transport.USB, 12345)
                .enabledCapabilities(Transport.NFC, 67890)
                .autoEjectTimeout((short)128)
                .challengeResponseTimeout((byte)55)
                .deviceFlags(98765)
                .build();
        assertEquals(Integer.valueOf(12345), defaultConfig.getEnabledCapabilities(Transport.USB));
        assertEquals(Integer.valueOf(67890), defaultConfig.getEnabledCapabilities(Transport.NFC));
        assertEquals(Short.valueOf((short)128), defaultConfig.getAutoEjectTimeout());
        assertEquals(Byte.valueOf((byte)55), defaultConfig.getChallengeResponseTimeout());
        assertEquals(Integer.valueOf(98765), defaultConfig.getDeviceFlags());
    }
}

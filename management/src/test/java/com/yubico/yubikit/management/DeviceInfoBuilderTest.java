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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class DeviceInfoBuilderTest {

    @Test
    public void testDefaults() {
        DeviceConfig defaultConfig = new DeviceConfig.Builder().build();
        DeviceInfo defaultInfo = new DeviceInfo.Builder().build();
        assertEquals(defaultConfig, defaultInfo.getConfig());
        assertNull(defaultInfo.getSerialNumber());
        assertEquals(new Version(0, 0, 0), defaultInfo.getVersion());
        assertEquals(FormFactor.UNKNOWN, defaultInfo.getFormFactor());
        assertEquals(0, defaultInfo.getSupportedCapabilities(Transport.USB));
        assertEquals(0, defaultInfo.getSupportedCapabilities(Transport.NFC));
        assertFalse(defaultInfo.isLocked());
        assertFalse(defaultInfo.isFips());
        assertFalse(defaultInfo.isSky());
        assertFalse(defaultInfo.getPinComplexity());
        assertFalse(defaultInfo.hasTransport(Transport.USB));
        assertFalse(defaultInfo.hasTransport(Transport.NFC));
    }

    @Test
    public void testConstruction() {
        Map<Transport, Integer> supportedCapabilities = new HashMap<>();
        supportedCapabilities.put(Transport.USB, 123);
        supportedCapabilities.put(Transport.NFC, 456);
        DeviceConfig deviceConfig = new DeviceConfig.Builder().build();
        DeviceInfo deviceInfo = new DeviceInfo.Builder()
                .config(deviceConfig)
                .serialNumber(987654321)
                .version(new Version(3, 1, 1))
                .formFactor(FormFactor.USB_A_KEYCHAIN)
                .supportedCapabilities(supportedCapabilities)
                .isLocked(true)
                .isFips(true)
                .isSky(true)
                .pinComplexity(true)
                .build();
        assertEquals(deviceConfig, deviceInfo.getConfig());
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
}

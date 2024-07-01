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
import static com.yubico.yubikit.support.TestUtil.info;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static java.lang.Boolean.FALSE;
import static java.lang.Boolean.TRUE;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.YubiKeyType;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.FormFactor;

import org.junit.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class AdjustDeviceInfoTest {

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
                Short.valueOf((short) 13288),
                info(i -> i.config(config(c -> c.autoEjectTimeout((short) 13288))))
                        .getConfig().getAutoEjectTimeout());
    }

    @Test
    public void testConfigChallengeResponseTimeout() {
        assertNull(
                info(i -> {
                }).getConfig().getChallengeResponseTimeout());

        assertEquals(
                Byte.valueOf((byte) 84),
                info(i -> i.config(config(c -> c.challengeResponseTimeout((byte) 84))))
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

    @Test
    public void testVersion() {
        assertEquals(
                new Version(0, 0, 0),
                info(i -> {
                }).getVersion());

        assertEquals(
                new Version(5, 7, 1),
                info(i -> i.version(new Version(5, 7, 1)))
                        .getVersion());
    }

    @Test
    public void testFormFactor() {
        assertEquals(
                FormFactor.UNKNOWN,
                info(i -> {
                }).getFormFactor());

        for (FormFactor formFactor : FormFactor.values()) {
            assertEquals(
                    formFactor,
                    info(i -> i.formFactor(formFactor))
                            .getFormFactor());
        }
    }

    @Test
    public void testSerialNumber() {
        assertNull(
                info(i -> {
                }).getSerialNumber());

        assertEquals(
                Integer.valueOf(232325454),
                info(i -> i.serialNumber(232325454))
                        .getSerialNumber());
    }

    @Test
    public void testIsLocked() {
        assertFalse(
                info(i -> {
                }).isLocked());

        assertTrue(
                info(i -> i.isLocked(true))
                        .isLocked());

        assertFalse(
                info(i -> i.isLocked(false))
                        .isLocked());
    }

    @Test
    public void testIsFips() {
        assertFalse(
                info(i -> {
                }).isFips());

        assertTrue(
                info(i -> i.isFips(true))
                        .isFips());

        assertFalse(
                info(i -> i.isFips(false))
                        .isFips());
    }

    @Test
    public void testIsSky() {
        assertFalse(
                info(i -> {
                }).isSky());

        assertTrue(
                info(i -> i.isSky(true))
                        .isSky());

        assertTrue(
                info(i -> i.isSky(false), YubiKeyType.SKY, 0)
                        .isSky());

        assertFalse(
                info(i -> i.isSky(false))
                        .isSky());
    }

    @Test
    public void testFipsCapable() {
        assertEquals(
                0,
                info(i -> {
                }).getFipsCapable());

        assertEquals(
                16384,
                info(i -> i.fipsCapable(16384))
                        .getFipsCapable());
    }

    @Test
    public void testFipsApproved() {
        assertEquals(
                0,
                info(i -> {
                }).getFipsApproved());

        assertEquals(
                65535,
                info(i -> i.fipsApproved(65535))
                        .getFipsApproved());
    }

    @Test
    public void testPartNumber() {
        assertEquals(
                "",
                info(i -> {
                }).getPartNumber());

        assertEquals(
                "0102030405060708",
                info(i -> i.partNumber("0102030405060708"))
                        .getPartNumber());
    }

    @Test
    public void testPinComplexity() {
        assertFalse(
                info(i -> {
                }).getPinComplexity());

        assertTrue(
                info(i -> i.pinComplexity(true))
                        .getPinComplexity());

        assertFalse(
                info(i -> i.pinComplexity(false))
                        .getPinComplexity());
    }

    @Test
    public void testResetBlocked() {
        assertEquals(
                0,
                info(i -> {
                }).getResetBlocked());

        assertEquals(
                22647,
                info(i -> i.resetBlocked(22647))
                        .getResetBlocked());
    }

    @Test
    public void testFpsVersion() {
        assertNull(
                info(i -> {
                }).getFpsVersion());

        assertEquals(
                new Version(1, 4, 2),
                info(i -> i.fpsVersion(new Version(1, 4, 2)))
                        .getFpsVersion());
    }

    @Test
    public void testStmVersion() {
        assertNull(
                info(i -> {
                }).getStmVersion());

        assertEquals(
                new Version(2, 4, 2),
                info(i -> i.stmVersion(new Version(2, 4, 2)))
                        .getStmVersion());
    }

    @Test
    public void testSupportedCapabilities() {
        // USB
        assertEquals(
                0,
                info(i -> {
                }).getSupportedCapabilities(Transport.USB));

        Map<Transport, Integer> supportedUsbCapabilities = new HashMap<>();
        supportedUsbCapabilities.put(Transport.USB, 4096);
        assertEquals(
                4096,
                info(i -> i.supportedCapabilities(supportedUsbCapabilities))
                        .getSupportedCapabilities(Transport.USB));

        Map<Transport, Integer> supportedNfcCapabilities = new HashMap<>();
        supportedNfcCapabilities.put(Transport.NFC, 4096);
        assertEquals(
                0,
                info(i -> i.supportedCapabilities(supportedNfcCapabilities))
                        .getSupportedCapabilities(Transport.USB));
        assertEquals(
                4096,
                info(i -> i.supportedCapabilities(supportedNfcCapabilities))
                        .getSupportedCapabilities(Transport.NFC));

        Map<Transport, Integer> supportedCapabilities = new HashMap<>();
        supportedCapabilities.put(Transport.NFC, 8192);
        supportedCapabilities.put(Transport.USB, 16384);
        assertEquals(
                16384,
                info(i -> i.supportedCapabilities(supportedCapabilities))
                        .getSupportedCapabilities(Transport.USB));
        assertEquals(
                8192,
                info(i -> i.supportedCapabilities(supportedCapabilities))
                        .getSupportedCapabilities(Transport.NFC));
    }

    @Test
    public void testEnabledNfcCapabilities() {
        Map<Transport, Integer> supportedCapabilities = new HashMap<>();
        supportedCapabilities.put(Transport.NFC, 8192);
        assertEquals(
                Integer.valueOf(4096),
                info(i -> {
                    i.supportedCapabilities(supportedCapabilities);
                    i.config(config(c -> c.enabledCapabilities(Transport.NFC, 4096)));
                }).getConfig().getEnabledCapabilities(Transport.NFC));

        // null enabled capabilities
        assertEquals(
                Integer.valueOf(8192),
                info(i -> i.supportedCapabilities(supportedCapabilities))
                        .getConfig().getEnabledCapabilities(Transport.NFC));

        List<FormFactor> usbOnlyFactors = new ArrayList<>();
        usbOnlyFactors.add(FormFactor.USB_A_NANO);
        usbOnlyFactors.add(FormFactor.USB_C_NANO);
        usbOnlyFactors.add(FormFactor.USB_C_LIGHTNING);
        usbOnlyFactors.add(FormFactor.USB_C_KEYCHAIN);

        for (FormFactor formFactor : usbOnlyFactors) {

            DeviceInfo info = info(i -> {
                i.formFactor(formFactor);
                i.supportedCapabilities(supportedCapabilities);
                i.version(new Version(5, 2, 3));
                i.config(config(c -> c.enabledCapabilities(Transport.NFC, 4096)));
            });

            assertNull(
                    info.getConfig().getEnabledCapabilities(Transport.NFC));

            assertEquals(
                    0,
                    info.getSupportedCapabilities(Transport.NFC)
            );

            if (formFactor == FormFactor.USB_C_KEYCHAIN) {
                info = info(i -> {
                    i.formFactor(formFactor);
                    i.supportedCapabilities(supportedCapabilities);
                    i.version(new Version(5, 2, 4));
                    i.config(config(c -> c.enabledCapabilities(Transport.NFC, 4096)));
                });

                assertEquals(
                        Integer.valueOf(4096),
                        info.getConfig().getEnabledCapabilities(Transport.NFC));

                assertEquals(
                        8192,
                        info.getSupportedCapabilities(Transport.NFC)
                );

                // null enabled capabilities
                info = info(i -> {
                    i.formFactor(formFactor);
                    i.supportedCapabilities(supportedCapabilities);
                    i.version(new Version(5, 2, 4));
                });

                assertEquals(
                        Integer.valueOf(8192),
                        info.getConfig().getEnabledCapabilities(Transport.NFC));

                assertEquals(
                        8192,
                        info.getSupportedCapabilities(Transport.NFC)
                );
            }
        }

    }

    @Test
    public void testEnabledUsbCapabilities() {
        Map<Transport, Integer> supportedCapabilities = new HashMap<>();
        supportedCapabilities.put(Transport.USB, 0b0111);

        // enabled usb capabilities are not null
        DeviceInfo info = info(i -> {
            i.supportedCapabilities(supportedCapabilities);
            i.config(config(c -> c.enabledCapabilities(Transport.USB, 0b1011)));
        });

        assertEquals(
                Integer.valueOf(0b1011),
                info.getConfig().getEnabledCapabilities(Transport.USB));

        assertEquals(
                0b0111,
                info.getSupportedCapabilities(Transport.USB));

        // no usb transport support
        // enabled usb capabilities are not null
        info = info(i -> {
            i.config(config(c -> c.enabledCapabilities(Transport.USB, 0b1011)));
        });

        assertEquals(
                Integer.valueOf(0b1011),
                info.getConfig().getEnabledCapabilities(Transport.USB));

        assertEquals(
                0,
                info.getSupportedCapabilities(Transport.USB));

        // null enabled capabilities
        info = info(i -> i.supportedCapabilities(supportedCapabilities));

        assertEquals(
                Integer.valueOf(0b0111),
                info.getConfig().getEnabledCapabilities(Transport.USB));

        assertEquals(
                0b0011,
                info.getSupportedCapabilities(Transport.USB));

        // with OTP interface
        info = info(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0111);

        assertEquals(
                Integer.valueOf(0b0111),
                info.getConfig().getEnabledCapabilities(Transport.USB));

        assertEquals(
                0b0011,
                info.getSupportedCapabilities(Transport.USB));

        // without OTP interface
        info = info(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0110);

        assertEquals(
                Integer.valueOf(0b0110),
                info.getConfig().getEnabledCapabilities(Transport.USB));

        assertEquals(
                0b0011,
                info.getSupportedCapabilities(Transport.USB));

        // add FIDO2 capability
        supportedCapabilities.put(Transport.USB, 0x207);
        // with FIDO interface
        info = info(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0111);

        assertEquals(
                Integer.valueOf(0x207),
                info.getConfig().getEnabledCapabilities(Transport.USB));

        assertEquals(
                0x207,
                info.getSupportedCapabilities(Transport.USB));

        // without FIDO interface
        supportedCapabilities.put(Transport.USB, 0x207);
        info = info(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0101);

        assertEquals(
                Integer.valueOf(0x5),
                info.getConfig().getEnabledCapabilities(Transport.USB));

        assertEquals(
                0x207,
                info.getSupportedCapabilities(Transport.USB));

        // all CCID capabilities (and FIDO2+U2F)
        supportedCapabilities.put(Transport.USB, 0x23A);
        // with CCID interface
        info = info(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0111);

        assertEquals(
                Integer.valueOf(0x23A),
                info.getConfig().getEnabledCapabilities(Transport.USB));

        assertEquals(
                0x23A,
                info.getSupportedCapabilities(Transport.USB));

        // without FIDO interface
        supportedCapabilities.put(Transport.USB, 0x23A);
        info = info(i -> i.supportedCapabilities(supportedCapabilities), null, 0b0011);

        assertEquals(
                Integer.valueOf(0x202),
                info.getConfig().getEnabledCapabilities(Transport.USB));

        assertEquals(
                0x23A,
                info.getSupportedCapabilities(Transport.USB));

    }
}

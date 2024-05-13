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

import static com.yubico.yubikit.management.TestUtil.defaultVersion;
import static com.yubico.yubikit.management.TestUtil.emptyTlvs;
import static com.yubico.yubikit.management.TestUtil.tlvs;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.Version;

import org.junit.Test;

public class DeviceInfoTest {

    @Test
    public void testParseSerialNumber() {
        assertNull(defaultInfo().getSerialNumber());
        assertEquals(Integer.valueOf(123456789), infoOf(0x02, new byte[]{0x07, 0x5b, (byte) 0xcd, 0x15}).getSerialNumber());
    }

    @Test
    public void testParseVersion() {
        assertEquals(new Version(5, 3, 4), infoOf(0x05, new byte[]{0x05, 0x03, 0x04}).getVersion());
    }

    @Test
    public void testUseDefaultVersion() {
        assertEquals(defaultVersion, defaultInfo().getVersion());
    }

    @Test
    public void testParseFormFactor() {
        assertEquals(FormFactor.UNKNOWN, defaultInfo().getFormFactor());
        assertEquals(FormFactor.USB_A_KEYCHAIN, infoOf(0x04, new byte[]{0x01}).getFormFactor());
        assertEquals(FormFactor.USB_A_NANO, infoOf(0x04, new byte[]{0x02}).getFormFactor());
        assertEquals(FormFactor.USB_C_KEYCHAIN, infoOf(0x04, new byte[]{0x03}).getFormFactor());
        assertEquals(FormFactor.USB_C_NANO, infoOf(0x04, new byte[]{0x04}).getFormFactor());
        assertEquals(FormFactor.USB_C_LIGHTNING, infoOf(0x04, new byte[]{0x05}).getFormFactor());
        assertEquals(FormFactor.USB_A_BIO, infoOf(0x04, new byte[]{0x06}).getFormFactor());
        assertEquals(FormFactor.USB_C_BIO, infoOf(0x04, new byte[]{0x07}).getFormFactor());
        // the form factor byte contains fips (0x80) and sky (0x40) flags
        assertEquals(FormFactor.USB_A_BIO, infoOf(0x04, new byte[]{0x46}).getFormFactor());
        assertEquals(FormFactor.USB_C_NANO, infoOf(0x04, new byte[]{(byte) 0x84}).getFormFactor());
    }

    @Test
    public void testParseLocked() {
        assertFalse(defaultInfo().isLocked());
        assertTrue(infoOf(0x0a, new byte[]{0x01}).isLocked());
        assertFalse(infoOf(0x0a, new byte[]{0x00}).isLocked());
    }

    @Test
    public void testParseFips() {
        assertFalse(defaultInfo().isFips());
        assertTrue(infoOf(0x04, new byte[]{(byte) 0x80}).isFips());
        assertTrue(infoOf(0x04, new byte[]{(byte) 0xC0}).isFips());
        assertFalse(infoOf(0x04, new byte[]{0x40}).isFips());
    }

    @Test
    public void testParseSky() {
        assertFalse(defaultInfo().isSky());
        assertTrue(infoOf(0x04, new byte[]{0x40}).isSky());
        assertTrue(infoOf(0x04, new byte[]{(byte) 0xC0}).isSky());
        assertFalse(infoOf(0x04, new byte[]{(byte) 0x80}).isSky());
    }

    @Test
    public void testParseFipsCapable() {
        assertEquals(0, defaultInfo().getFipsCapable());
        assertEquals(15, infoOf(0x14, new byte[]{0x00, 0x0F}).getFipsCapable());
    }

    @Test
    public void testParseFipsApproved() {
        assertEquals(0, defaultInfo().getFipsApproved());
        assertEquals(31, infoOf(0x15, new byte[]{0x00, 0x1F}).getFipsApproved());
    }

    @Test
    public void testParsePinComplexity() {
        assertFalse(defaultInfo().getPinComplexity());
        assertFalse(infoOf(0x16, new byte[]{0x00}).getPinComplexity());
        assertTrue(infoOf(0x16, new byte[]{0x01}).getPinComplexity());
    }

    @Test
    public void testParseResetBlocked() {
        assertEquals(0, defaultInfo().getResetBlocked());
        assertEquals(1056, infoOf(0x18, new byte[]{0x04, 0x20}).getResetBlocked());
    }

    @Test
    public void testParseFpsVersion() {
        assertNull(defaultInfo().getFpsVersion());
        assertEquals(new Version(5, 6, 6), infoOf(0x20, new byte[]{0x05, 0x06, 0x06}).getFpsVersion());
    }

    @Test
    public void testParseStmVersion() {
        assertNull(defaultInfo().getStmVersion());
        assertEquals(new Version(7, 0, 5), infoOf(0x21, new byte[]{0x07, 0x00, 0x05}).getStmVersion());
    }

    private DeviceInfo defaultInfo() {
        return DeviceInfo.parseTlvs(emptyTlvs(), defaultVersion);
    }

    private DeviceInfo infoOf(int tag, byte[] data) {
        return DeviceInfo.parseTlvs(tlvs(tag, data), defaultVersion);
    }
}


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

import static com.yubico.yubikit.management.FormFactor.UNKNOWN;
import static com.yubico.yubikit.management.FormFactor.USB_A_BIO;
import static com.yubico.yubikit.management.FormFactor.USB_A_KEYCHAIN;
import static com.yubico.yubikit.management.FormFactor.USB_A_NANO;
import static com.yubico.yubikit.management.FormFactor.USB_C_BIO;
import static com.yubico.yubikit.management.FormFactor.USB_C_KEYCHAIN;
import static com.yubico.yubikit.management.FormFactor.USB_C_LIGHTNING;
import static com.yubico.yubikit.management.FormFactor.USB_C_NANO;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.YubiKeyType;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;

import org.junit.Test;

import java.util.HashMap;

public class DeviceUtilTest {

    final YubiKeyType keyType = YubiKeyType.YK4;

    @Test
    public void testGetNameYubiKeyUnknownFormFactor() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .formFactor(UNKNOWN)
                .version(new Version(5, 4, 3))
                .supportedCapabilities(yk5UsbOnlyCapabilities);

        assertEquals("YubiKey 5",
                DeviceUtil.getName(builder.build(), keyType));
        assertEquals("YubiKey 5 NFC",
                DeviceUtil.getName(builder.supportedCapabilities(yk5Capabilities)
                        .build(), keyType));
    }

    @Test
    public void testGetNameYubiKey5() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .formFactor(USB_A_KEYCHAIN)
                .version(new Version(5, 4, 3))
                .supportedCapabilities(yk5UsbOnlyCapabilities);

        assertEquals("YubiKey 5A",
                DeviceUtil.getName(builder.build(), keyType));
        assertEquals("YubiKey 5C",
                DeviceUtil.getName(builder.formFactor(USB_C_KEYCHAIN).build(), keyType));
    }

    @Test
    public void testGetNameYubiKey5Nfc() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .formFactor(USB_A_KEYCHAIN)
                .version(new Version(5, 4, 3))
                .supportedCapabilities(yk5Capabilities);

        assertEquals("YubiKey 5 NFC",
                DeviceUtil.getName(builder.build(), keyType));
        assertEquals("YubiKey 5C NFC",
                DeviceUtil.getName(builder.formFactor(USB_C_KEYCHAIN).build(), keyType));
    }

    @Test
    public void testGetNameYubiKey5Nano() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .formFactor(USB_A_NANO)
                .version(new Version(5, 4, 3))
                .supportedCapabilities(yk5UsbOnlyCapabilities);

        assertEquals("YubiKey 5 Nano",
                DeviceUtil.getName(builder.build(), keyType));
        assertEquals("YubiKey 5C Nano",
                DeviceUtil.getName(builder.formFactor(USB_C_NANO).build(), keyType));
    }

    @Test
    public void testGetNameYubiKey5Lightning() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .formFactor(USB_C_LIGHTNING)
                .version(new Version(5, 4, 3))
                .supportedCapabilities(yk5UsbOnlyCapabilities);

        assertEquals("YubiKey 5Ci",
                DeviceUtil.getName(builder.build(), keyType));
    }


    @Test
    public void testGetNameSecurityKey() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .version(new Version(5, 6, 0))
                .isSky(true)
                .formFactor(USB_A_KEYCHAIN)
                .supportedCapabilities(fidoCapabilities);

        assertEquals("Security Key NFC",
                DeviceUtil.getName(builder.build(), keyType));
        assertEquals("Security Key C NFC",
                DeviceUtil.getName(builder.formFactor(USB_C_KEYCHAIN).build(), keyType));
    }

    @Test
    public void testGetNameFips() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .version(new Version(5, 6, 0))
                .isFips(true)
                .formFactor(USB_A_KEYCHAIN)
                .supportedCapabilities(yk5Capabilities);

        assertEquals("YubiKey 5 NFC FIPS",
                DeviceUtil.getName(builder.build(), keyType));
        assertEquals("YubiKey 5C NFC FIPS",
                DeviceUtil.getName(builder.formFactor(USB_C_KEYCHAIN).build(), keyType));
        assertEquals("YubiKey 5A FIPS",
                DeviceUtil.getName(builder.formFactor(USB_A_KEYCHAIN)
                        .supportedCapabilities(yk5UsbOnlyCapabilities).build(), keyType));
        assertEquals("YubiKey 5C FIPS",
                DeviceUtil.getName(builder.formFactor(USB_C_KEYCHAIN).build(), keyType));
    }

    @Test
    public void testGetNameYubiKey4Fips() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .formFactor(USB_A_KEYCHAIN)
                .version(new Version(4, 0, 0))
                .supportedCapabilities(yk4Capabilities)
                .isFips(true);

        assertEquals("YubiKey FIPS",
                DeviceUtil.getName(builder.build(), YubiKeyType.YK4));
    }

    @Test
    public void testGetNameYubiKeyEdge() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .formFactor(USB_A_KEYCHAIN)
                .version(new Version(4, 0, 0))
                .supportedCapabilities(edgeCapabilities);

        assertEquals("YubiKey Edge",
                DeviceUtil.getName(builder.build(), YubiKeyType.YK4));
    }

    @Test
    public void testGetNameYubiKey4() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .formFactor(USB_A_KEYCHAIN)
                .version(new Version(4, 0, 0))
                .supportedCapabilities(yk4Capabilities);

        assertEquals("YubiKey 4",
                DeviceUtil.getName(builder.build(), YubiKeyType.YK4));
    }

    @Test
    public void testGetNameBioSeriesFidoEdition() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .version(new Version(5, 6, 6))
                .formFactor(USB_A_BIO)
                .supportedCapabilities(bioCapabilities)
                .serialNumber(null);

        assertEquals("YubiKey Bio - FIDO Edition",
                DeviceUtil.getName(builder.build(), keyType));
        assertEquals("YubiKey C Bio - FIDO Edition",
                DeviceUtil.getName(builder.formFactor(USB_C_BIO).build(), keyType));
    }

    @Test
    public void testGetNameBioSeriesMultiProtocolEdition() {
        // multi-protocol has PIV and a serial number
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .version(new Version(5, 6, 6))
                .formFactor(USB_A_BIO)
                .supportedCapabilities(bioMultiProtocolCapabilities)
                .serialNumber(12345);

        assertEquals("YubiKey Bio - Multi-protocol Edition",
                DeviceUtil.getName(builder.build(), keyType));
        assertEquals("YubiKey C Bio - Multi-protocol Edition",
                DeviceUtil.getName(builder.formFactor(USB_C_BIO).build(), keyType));
    }

    @Test
    public void testGetNameSecurityKeyEnterpriseEdition() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .version(new Version(5, 4, 3))
                .isSky(true)
                .formFactor(USB_A_KEYCHAIN)
                .supportedCapabilities(fidoCapabilities)
                .serialNumber(65454545);

        assertEquals("Security Key NFC - Enterprise Edition",
                DeviceUtil.getName(builder.build(), keyType));
        assertEquals("Security Key C NFC - Enterprise Edition",
                DeviceUtil.getName(builder.formFactor(USB_C_KEYCHAIN).build(), keyType));
    }

    @Test
    public void testGetNameYubiKeyPreview() {
        final DeviceInfo.Builder builder = new DeviceInfo.Builder()
                .formFactor(USB_A_KEYCHAIN)
                .version(new Version(5, 0, 0))
                .supportedCapabilities(yk5UsbOnlyCapabilities);

        assertEquals("YubiKey Preview",
                DeviceUtil.getName(builder.build(), keyType));
        assertEquals("YubiKey Preview",
                DeviceUtil.getName(builder.version(new Version(5, 0, 10)).build(), keyType));
        assertNotEquals("YubiKey Preview",
                DeviceUtil.getName(builder.version(new Version(5, 1, 0)).build(), keyType));
        assertEquals("YubiKey Preview",
                DeviceUtil.getName(builder.version(new Version(5, 2, 2)).build(), keyType));
        assertNotEquals("YubiKey Preview",
                DeviceUtil.getName(builder.version(new Version(5, 2, 3)).build(), keyType));
        assertEquals("YubiKey Preview",
                DeviceUtil.getName(builder.version(new Version(5, 5, 1)).build(), keyType));
        assertNotEquals("YubiKey Preview",
                DeviceUtil.getName(builder.version(new Version(5, 5, 3)).build(), keyType));

    }

    final static int fidoBits = Capability.FIDO2.bit | Capability.U2F.bit;
    final static HashMap<Transport, Integer> fidoCapabilities = new HashMap<Transport, Integer>() {{
        put(Transport.USB, fidoBits);
        put(Transport.NFC, fidoBits);
    }};

    final static HashMap<Transport, Integer> bioCapabilities = new HashMap<Transport, Integer>() {{
        put(Transport.USB, fidoBits);
    }};

    final static HashMap<Transport, Integer> bioMultiProtocolCapabilities = new HashMap<Transport, Integer>() {{
        put(Transport.USB, fidoBits | Capability.PIV.bit);
    }};

    final static HashMap<Transport, Integer> yk5UsbOnlyCapabilities = new HashMap<Transport, Integer>() {{
        put(Transport.USB, fidoBits | Capability.OATH.bit | Capability.PIV.bit | Capability.OPENPGP.bit | Capability.OTP.bit);
    }};

    final static HashMap<Transport, Integer> yk5Capabilities = new HashMap<Transport, Integer>() {{
        int capabilities = fidoBits | Capability.OATH.bit | Capability.PIV.bit | Capability.OPENPGP.bit | Capability.OTP.bit;
        put(Transport.USB, capabilities);
        put(Transport.NFC, capabilities);
    }};

    final static HashMap<Transport, Integer> yk4Capabilities = new HashMap<Transport, Integer>() {{
        int capabilities = Capability.U2F.bit | Capability.OATH.bit | Capability.PIV.bit | Capability.OPENPGP.bit | Capability.OTP.bit;
        put(Transport.USB, capabilities);
        put(Transport.NFC, capabilities);
    }};

    final static HashMap<Transport, Integer> edgeCapabilities = new HashMap<Transport, Integer>() {{
        int capabilities = Capability.U2F.bit | Capability.OTP.bit;
        put(Transport.USB, capabilities);
    }};
}

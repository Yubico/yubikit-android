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

import static com.yubico.yubikit.management.Capability.FIDO2;
import static com.yubico.yubikit.management.Capability.OTP;
import static com.yubico.yubikit.management.Capability.U2F;
import static com.yubico.yubikit.support.Util.isFidoOnly;
import static com.yubico.yubikit.support.YubiKeyTypeName.nameByYubiKeyType;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.FormFactor;

import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;
import java.util.function.Function;

import javax.annotation.Nonnull;

public class Device {
    /**
     * @return product name of the YubiKey
     */
    public static String getName(@Nonnull DeviceInfo deviceInfo) {

        int supportedUsbCapabilities = deviceInfo.getSupportedCapabilities(Transport.USB);

        Function<Capability, Boolean> supportsCapability =
                (capability) -> (supportedUsbCapabilities & capability.bit) == capability.bit;

        YubiKeyType yubiKeyType =
                (deviceInfo.getSerialNumber() == null &&
                        isFidoOnly(supportedUsbCapabilities)) ?
                        YubiKeyType.SKY : (deviceInfo.getVersion().major == 3) ?
                        YubiKeyType.NEO : YubiKeyType.YK4;

        String deviceName = nameByYubiKeyType.get(yubiKeyType);

        if (yubiKeyType == YubiKeyType.SKY) {
            if (supportsCapability.apply(FIDO2)) {
                deviceName = "FIDO U2F Security Key"; // SKY 1
            }
            if (deviceInfo.hasTransport(Transport.NFC)) {
                deviceName = "Security Key NFC";
            }
        } else if (yubiKeyType == YubiKeyType.YK4) {
            int majorVersion = deviceInfo.getVersion().major;
            if (majorVersion < 4) {
                if (majorVersion == 0) {
                    return "YubiKey (" + deviceInfo.getVersion() + ")";
                } else {
                    return "YubiKey";
                }
            } else if (majorVersion == 4) {
                if (VersionUtil.isFips(deviceInfo.getVersion())) {
                    //YK4 FIPS
                    deviceName = "YubiKey FIPS";
                } else if (supportsCapability.apply(OTP) || supportsCapability.apply(U2F)) {
                    deviceName = "YubiKey Edge";
                } else {
                    deviceName = "YubiKey 4";
                }
            }
        }

        if (VersionUtil.isPreview(deviceInfo.getVersion())) {
            deviceName = "YubiKey Preview";
        } else if (deviceInfo.getVersion().isAtLeast(5, 1, 0)) {
            boolean isNano = deviceInfo.getFormFactor() == FormFactor.USB_A_NANO
                    || deviceInfo.getFormFactor() == FormFactor.USB_C_NANO;
            boolean isBio = deviceInfo.getFormFactor() == FormFactor.USB_A_BIO
                    || deviceInfo.getFormFactor() == FormFactor.USB_C_BIO;
            // does not include Ci
            boolean isC = deviceInfo.getFormFactor() == FormFactor.USB_C_KEYCHAIN
                    || deviceInfo.getFormFactor() == FormFactor.USB_C_NANO
                    || deviceInfo.getFormFactor() == FormFactor.USB_C_BIO;


            List<String> namePartsList = new ArrayList<>();
            if (deviceInfo.isSky()) {
                namePartsList.add("Security Key");
            } else {
                namePartsList.add("YubiKey");
                if (!isBio) {
                    namePartsList.add("5");
                }
            }

            if (isC) {
                namePartsList.add("C");
            } else if (deviceInfo.getFormFactor() == FormFactor.USB_C_LIGHTNING) {
                namePartsList.add("Ci");
            }

            if (isNano) {
                namePartsList.add("Nano");
            }

            if (deviceInfo.hasTransport(Transport.NFC)) {
                namePartsList.add("NFC");
            } else if (deviceInfo.getFormFactor() == FormFactor.USB_A_KEYCHAIN) {
                namePartsList.add("A"); // only for non-NFC A Keychain
            }

            if (isBio) {
                namePartsList.add("Bio");
                if (isFidoOnly(supportedUsbCapabilities)) {
                    namePartsList.add("- FIDO Edition");
                }
            }

            if (deviceInfo.isFips()) {
                namePartsList.add("FIPS");
            }

            StringJoiner joiner = new StringJoiner(" ");
            for (String s : namePartsList) {
                joiner.add(s);
            }
            deviceName = joiner.toString()
                    .replace("5 C", "5C")
                    .replace("5 A", "5A");


        }
        return deviceName;
    }

}

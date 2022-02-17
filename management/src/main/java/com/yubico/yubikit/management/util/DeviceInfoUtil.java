package com.yubico.yubikit.management.util;

import static com.yubico.yubikit.management.Capability.FIDO2;
import static com.yubico.yubikit.management.Capability.OTP;
import static com.yubico.yubikit.management.Capability.U2F;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.FormFactor;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.StringJoiner;
import java.util.function.Function;

import javax.annotation.Nonnull;

public class DeviceInfoUtil {

    private static final Map<YubiKeyType, String> yubiKeyName;

    static {
        Map<YubiKeyType, String> initMap = new LinkedHashMap<>();
        initMap.put(YubiKeyType.YKS, "YubiKey Standard");
        initMap.put(YubiKeyType.NEO, "YubiKey NEO");
        initMap.put(YubiKeyType.SKY, "Security Key by Yubico");
        initMap.put(YubiKeyType.YKP, "YubiKey Plus");
        initMap.put(YubiKeyType.YK4, "YubiKey");

        yubiKeyName = Collections.unmodifiableMap(initMap);
    }

    private static boolean isFidoOnly(int usbCapabilities) {
        return (usbCapabilities & ~(U2F.bit | FIDO2.bit)) == 0;
    }

    private static boolean isFipsVersion(Version version) {
        return version.isAtLeast(4, 4, 0) && version.isLessThan(4, 5, 0);
    }

    private static boolean isPreview(Version version) {
        return (version.isAtLeast(5, 0, 0) && version.isLessThan(5, 1, 0))
                || (version.isAtLeast(5, 2, 0) && version.isLessThan(5, 2, 3))
                || (version.isAtLeast(5, 5, 0) && version.isLessThan(5, 5, 2));
    }

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

        String deviceName = yubiKeyName.get(yubiKeyType);

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
                if (isFipsVersion(deviceInfo.getVersion())) {
                    //YK4 FIPS
                    deviceName = "YubiKey FIPS";
                } else if (supportsCapability.apply(OTP) || supportsCapability.apply(U2F)) {
                    deviceName = "YubiKey Edge";
                } else {
                    deviceName = "YubiKey 4";
                }
            }
        }

        if (isPreview(deviceInfo.getVersion())) {
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

    enum YubiKeyType {
        YKS,
        NEO,
        SKY,
        YKP,
        YK4
    }
}

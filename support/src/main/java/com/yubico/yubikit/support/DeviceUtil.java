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
import static com.yubico.yubikit.management.Capability.OATH;
import static com.yubico.yubikit.management.Capability.OPENPGP;
import static com.yubico.yubikit.management.Capability.OTP;
import static com.yubico.yubikit.management.Capability.PIV;
import static com.yubico.yubikit.management.Capability.U2F;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceConfig;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.FormFactor;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.management.UsbInterface;
import com.yubico.yubikit.yubiotp.YubiOtpSession;

import java.io.IOException;
import java.security.InvalidParameterException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;

public class DeviceUtil {

    // Applet and capability it provides
    private enum CcidApplet {
        OPENPGP(new byte[]{(byte) 0xd2, 0x76, 0x00, 0x01, 0x24, 0x01}, Capability.OPENPGP),
        OATH(new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x21, 0x01}, Capability.OATH),
        PIV(new byte[]{(byte) 0xa0, 0x00, 0x00, 0x03, 0x08}, Capability.PIV),
        FIDO(new byte[]{(byte) 0xa0, 0x00, 0x00, 0x06, 0x47, 0x2f, 0x00, 0x01}, U2F),
        AID_U2F_YUBICO(new byte[]{(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x10, 0x02}, U2F);  // Old U2F AID

        final public byte[] aid;
        final public Capability capability;

        CcidApplet(byte[] aid, Capability capability) {
            this.aid = aid;
            this.capability = capability;
        }
    }

    private static final Integer baseNeoApps = OTP.bit | OATH.bit | PIV.bit | OPENPGP.bit;

    static Pair<Version, Optional<Integer>> readOtpData(SmartCardConnection connection)
            throws ApplicationNotAvailableException, IOException {

        YubiOtpSession otpSession = new YubiOtpSession((SmartCardConnection) connection);

        Optional<Integer> serialNumber = Optional.empty();
        try {
            serialNumber = Optional.of(otpSession.getSerialNumber());
        } catch (CommandException commandException) {
            Logger.e("Unable to read serial over OTP, no serial", commandException);
        }

        return new Pair<>(otpSession.getVersion(), serialNumber);

    }

    static DeviceInfo readInfoCcid(SmartCardConnection connection, int interfaces)
            throws IOException {

        Version version = null;

        try {
            ManagementSession managementSession = new ManagementSession(connection);
            version = managementSession.getVersion();
            try {
                return managementSession.getDeviceInfo();
            } catch (UnsupportedOperationException | CommandException ignored) {
                // device does not support FEATURE_DEVICE_INFO
                // we ignore this exception and synthesize the information
            }
        } catch (ApplicationNotAvailableException ignored) {
            Logger.d("Couldn't select Management application, use fallback");
        }

        int capabilities = 0;
        Integer serial = null;

        try {
            Pair<Version, Optional<Integer>> otpData = readOtpData(connection);
            capabilities |= OTP.bit;
            if (version == null) {
                version = otpData.first;
            }
            serial = otpData.second.orElse(null);
        } catch (IOException | ApplicationNotAvailableException e) {
            Logger.d("Couldn't select OTP application, serial unknown");
        }

        if (version == null) {
            Logger.d("Firmware version unknown, using 3.0.0 as a baseline");
            version = new Version(3, 0, 0);
        }

        Logger.d("Scan for available ccid applications");
        SmartCardProtocol protocol = new SmartCardProtocol(connection);
        for (final CcidApplet applet : CcidApplet.values()) {
            try {
                protocol.select(applet.aid);
                capabilities |= applet.capability.bit;
            } catch (ApplicationNotAvailableException applicationNotAvailableException) {
                Logger.d("Missing applet " + applet.name() + ", capability " + applet.capability.name());
            } catch (IOException ioException) {
                Logger.e("IOException selecting applet " + applet.name() + ", capability " + applet.capability.name(), ioException);
            }
        }

        if (((interfaces & UsbInterface.FIDO) != 0) || version.isAtLeast(3, 3, 0)) {
            capabilities |= U2F.bit;
        }

        Map<Transport, Integer> supportedCapabilities = new EnumMap<>(Transport.class);
        supportedCapabilities.put(Transport.USB, capabilities);
        supportedCapabilities.put(Transport.NFC, capabilities);

        return new DeviceInfo(
                new DeviceConfig.Builder().build(),
                serial,
                version,
                FormFactor.UNKNOWN,
                supportedCapabilities,
                false,
                false,
                false);

    }

    static DeviceInfo readInfoOtp(OtpConnection connection, YubiKeyType keyType, int interfaces)
            throws IOException {

        ManagementSession managementSession = null;
        YubiOtpSession otpSession = null;

        int serial = 0;
        Version version;

        try {
            managementSession = new ManagementSession(connection);
        } catch (ApplicationNotAvailableException ignored) {
            // we could not get the management session for this connection
            // we try to get the YubiOtpSession
            otpSession = new YubiOtpSession(connection);
        }

        // Retry during potential reclaim timeout period (~3s).
        for (int i = 0; i < 8; i++) {
            try {
                if (otpSession == null) {
                    try {
                        return managementSession.getDeviceInfo();
                    } catch (CommandException ignored) {
                        // can be caused by retained state
                        otpSession = new YubiOtpSession(connection);
                    }
                    serial = otpSession.getSerialNumber();
                }
            } catch (CommandException commandException) {
                // can be caused by retained state
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ignored) {
                    // ignoring interrupted exception
                }
            }

        }

        version = otpSession.getVersion();
        int usbSupported;
        Map<Transport, Integer> capabilities = new EnumMap<>(Transport.class);

        if (keyType == YubiKeyType.NEO) {
            usbSupported = baseNeoApps;
            if ((interfaces & UsbInterface.FIDO) != 0 || version.isAtLeast(3, 0, 0)) {
                usbSupported |= U2F.bit;
            }
            capabilities.put(Transport.USB, usbSupported);
            capabilities.put(Transport.NFC, usbSupported);
        } else if (keyType == YubiKeyType.YKP) {
            capabilities.put(Transport.USB, OTP.bit | U2F.bit);
        } else {
            capabilities.put(Transport.USB, OTP.bit);
        }

        return new DeviceInfo(
                new DeviceConfig.Builder().build(), // defaults
                serial,
                version,
                FormFactor.UNKNOWN,
                capabilities,
                false,
                false,
                false);
    }

    static DeviceInfo readInfoFido(FidoConnection connection, YubiKeyType keyType)
            throws IOException {
        try {
            ManagementSession session = new ManagementSession(connection);
            return session.getDeviceInfo();
        } catch (CommandException exception) {
            Logger.d("Unable to get info via Management application, using fallback");

            final Version version =
                    keyType == YubiKeyType.YKP ?
                            new Version(4, 0, 0) :
                            new Version(3, 0, 0);

            Map<Transport, Integer> supportedApps = new EnumMap<>(Transport.class);
            supportedApps.put(Transport.USB, U2F.bit);
            if (keyType == YubiKeyType.NEO) {
                int usbApps = supportedApps.get(Transport.USB);
                supportedApps.replace(Transport.USB, usbApps | baseNeoApps);
                supportedApps.put(Transport.NFC, supportedApps.get(Transport.USB));
            }

            return new DeviceInfo(
                    new DeviceConfig.Builder().build(), // defaults
                    null,
                    version,
                    FormFactor.USB_A_KEYCHAIN,
                    supportedApps,
                    false,
                    false,
                    false);
        }
    }

    static boolean isPreviewVersion(Version version) {
        return (version.isAtLeast(5, 0, 0) && version.isLessThan(5, 1, 0))
                || (version.isAtLeast(5, 2, 0) && version.isLessThan(5, 2, 3))
                || (version.isAtLeast(5, 5, 0) && version.isLessThan(5, 5, 2));
    }

    /**
     * Returns DeviceInfo for connected YubiKey
     *
     * @param pid        USB product ID of the YubiKey, can be null if unknown
     * @param connection established connection to the YubiKey
     * @throws IOException               in case of connection error
     * @throws InvalidParameterException in case of unsupported connection parameter
     */
    public static DeviceInfo readInfo(@Nullable YubiKeyUsbProductId pid, YubiKeyConnection connection)
            throws IOException, InvalidParameterException {

        final YubiKeyType keyType = pid == null ? null : pid.type;
        final int interfaces = pid == null ? 0 : pid.usbInterfaces;

        DeviceInfo info;
        if (connection instanceof SmartCardConnection) {
            info = readInfoCcid((SmartCardConnection) connection, interfaces);
        } else if (connection instanceof OtpConnection) {
            info = readInfoOtp((OtpConnection) connection, keyType, interfaces);
        } else if (connection instanceof FidoConnection) {
            info = readInfoFido((FidoConnection) connection, keyType);
        } else {
            throw new InvalidParameterException("Invalid connection type");
        }

        Logger.d("Read info " + info);

        final DeviceConfig config = info.getConfig();
        final Version version = info.getVersion();
        final FormFactor formFactor = info.getFormFactor();

        @SuppressWarnings("WrapperTypeMayBePrimitive")
        Integer supportedUsbCapabilities = info.getSupportedCapabilities(Transport.USB);
        Integer supportedNfcCapabilities = info.getSupportedCapabilities(Transport.NFC);

        Integer enabledUsbCapabilities = config.getEnabledCapabilities(Transport.USB);
        Integer enabledNfcCapabilities = config.getEnabledCapabilities(Transport.NFC);

        // Set usbEnabled if missing (pre YubiKey 5)
        if (info.hasTransport(Transport.USB) && enabledUsbCapabilities == null) {

            int usbEnabled = supportedUsbCapabilities;
            if (usbEnabled == (OTP.bit | U2F.bit | UsbInterface.CCID)) {
                // YubiKey Edge, hide unusable CCID interface from supported
                supportedUsbCapabilities = OTP.bit | U2F.bit;
            }

            if ((interfaces & UsbInterface.OTP) == 0) {
                usbEnabled &= ~OTP.bit;
            }

            if ((interfaces & UsbInterface.FIDO) == 0) {
                usbEnabled &= ~(U2F.bit | FIDO2.bit);
            }

            if ((interfaces & UsbInterface.CCID) == 0) {
                usbEnabled &= ~(UsbInterface.CCID | OATH.bit | OPENPGP.bit | PIV.bit);
            }

            enabledUsbCapabilities = usbEnabled;
        }

        boolean isSky = info.isSky();
        if (keyType == YubiKeyType.SKY) {
            isSky = true;
        }

        boolean isFips = info.isFips();
        // YK4-based FIPS version
        if (version.isAtLeast(4, 4, 0) && version.isLessThan(4, 5, 0)) {
            isFips = true;
        }

        // Set nfc_enabled if missing (pre YubiKey 5)
        if (info.hasTransport(Transport.NFC) && enabledNfcCapabilities == null) {
            enabledNfcCapabilities = supportedNfcCapabilities;
        }

        // Workaround for invalid configurations.
        if (version.isAtLeast(4, 0, 0)) {
            if (formFactor == FormFactor.USB_A_NANO
                    || formFactor == FormFactor.USB_C_NANO
                    || formFactor == FormFactor.USB_C_LIGHTNING
                    || (formFactor == FormFactor.USB_C_KEYCHAIN
                    && version.isLessThan(5, 2, 4))) {
                // Known not to have NFC
                supportedNfcCapabilities = null;
                enabledNfcCapabilities = null;
            }
        }

        final Integer deviceFlags = config.getDeviceFlags();
        final Short autoEjectTimeout = config.getAutoEjectTimeout();
        final Byte challengeResponseTimeout = config.getChallengeResponseTimeout();

        DeviceConfig.Builder configBuilder = new DeviceConfig.Builder();
        if (deviceFlags != null) {
            configBuilder.deviceFlags(deviceFlags);
        }

        if (autoEjectTimeout != null) {
            configBuilder.autoEjectTimeout(autoEjectTimeout);
        }

        if (challengeResponseTimeout != null) {
            configBuilder.challengeResponseTimeout(challengeResponseTimeout);
        }

        if (enabledNfcCapabilities != null) {
            configBuilder.enabledCapabilities(Transport.NFC, enabledNfcCapabilities);
        }

        if (enabledUsbCapabilities != null) {
            configBuilder.enabledCapabilities(Transport.USB, enabledUsbCapabilities);
        }

        Map<Transport, Integer> capabilities = new EnumMap<>(Transport.class);
        capabilities.put(Transport.USB, supportedUsbCapabilities);
        capabilities.put(Transport.NFC, supportedNfcCapabilities);

        return new DeviceInfo(
                configBuilder.build(),
                info.getSerialNumber(),
                version,
                formFactor,
                capabilities,
                info.isLocked(),
                isFips,
                isSky
        );

    }

    /**
     * Returns computed product name for a YubiKey device, based on the provided DeviceInfo
     */
    public static String getName(@Nonnull DeviceInfo info) {

        final Version version = info.getVersion();
        final FormFactor formFactor = info.getFormFactor();

        final int supportedUsbCapabilities = info.getSupportedCapabilities(Transport.USB);
        final boolean isFidoOnly = (supportedUsbCapabilities & ~(U2F.bit | FIDO2.bit)) == 0;

        final YubiKeyType yubiKeyType = (info.getSerialNumber() == null && isFidoOnly) ?
                YubiKeyType.SKY : (version.major == 3) ?
                YubiKeyType.NEO : YubiKeyType.YK4;

        String deviceName = yubiKeyType.name;

        if (yubiKeyType == YubiKeyType.SKY) {
            if ((supportedUsbCapabilities & FIDO2.bit) == FIDO2.bit) {
                deviceName = "FIDO U2F Security Key"; // SKY 1
            }
            if (info.hasTransport(Transport.NFC)) {
                deviceName = "Security Key NFC";
            }
        } else if (yubiKeyType == YubiKeyType.YK4) {
            int majorVersion = version.major;
            if (majorVersion < 4) {
                if (majorVersion == 0) {
                    return "YubiKey (" + version + ")";
                } else {
                    return "YubiKey";
                }
            } else if (majorVersion == 4) {
                if (info.isFips()) {
                    //YK4 FIPS
                    deviceName = "YubiKey FIPS";
                } else if ((supportedUsbCapabilities & (OTP.bit | U2F.bit)) != 0) {
                    deviceName = "YubiKey Edge";
                } else {
                    deviceName = "YubiKey 4";
                }
            }
        }

        if (isPreviewVersion(version)) {
            deviceName = "YubiKey Preview";
        } else if (version.isAtLeast(5, 1, 0)) {
            boolean isNano = formFactor == FormFactor.USB_A_NANO
                    || formFactor == FormFactor.USB_C_NANO;
            boolean isBio = formFactor == FormFactor.USB_A_BIO
                    || formFactor == FormFactor.USB_C_BIO;
            // does not include Ci
            boolean isC = formFactor == FormFactor.USB_C_KEYCHAIN
                    || formFactor == FormFactor.USB_C_NANO
                    || formFactor == FormFactor.USB_C_BIO;


            List<String> namePartsList = new ArrayList<>();
            if (info.isSky()) {
                namePartsList.add("Security Key");
            } else {
                namePartsList.add("YubiKey");
                if (!isBio) {
                    namePartsList.add("5");
                }
            }

            if (isC) {
                namePartsList.add("C");
            } else if (formFactor == FormFactor.USB_C_LIGHTNING) {
                namePartsList.add("Ci");
            }

            if (isNano) {
                namePartsList.add("Nano");
            }

            if (info.hasTransport(Transport.NFC)) {
                namePartsList.add("NFC");
            } else if (formFactor == FormFactor.USB_A_KEYCHAIN) {
                namePartsList.add("A"); // only for non-NFC A Keychain
            }

            if (isBio) {
                namePartsList.add("Bio");
                if (isFidoOnly) {
                    namePartsList.add("- FIDO Edition");
                }
            }

            if (info.isFips()) {
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

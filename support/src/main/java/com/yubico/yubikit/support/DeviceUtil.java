/*
 * Copyright (C) 2022-2025 Yubico.
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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbInterface;
import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyType;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.SessionVersionOverride;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceConfig;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.FormFactor;
import com.yubico.yubikit.management.ManagementSession;
import com.yubico.yubikit.yubiotp.YubiOtpSession;
import java.io.IOException;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

public class DeviceUtil {

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(DeviceUtil.class);
  private static final Integer baseNeoApps =
      Capability.OTP.bit | Capability.OATH.bit | Capability.PIV.bit | Capability.OPENPGP.bit;

  static class OtpData {
    final Version version;
    final @Nullable Integer serial;

    public OtpData(Version version, @Nullable Integer serial) {
      this.version = version;
      this.serial = serial;
    }
  }

  static OtpData readOtpData(SmartCardConnection connection)
      throws ApplicationNotAvailableException, IOException {

    YubiOtpSession otpSession = new YubiOtpSession(connection);

    Integer serialNumber = null;
    try {
      serialNumber = otpSession.getSerialNumber();
    } catch (CommandException commandException) {
      Logger.error(logger, "Unable to read serial over OTP, no serial", commandException);
    }

    return new OtpData(otpSession.getVersion(), serialNumber);
  }

  static DeviceInfo readInfoCcid(SmartCardConnection connection, int interfaces)
      throws IOException {

    boolean managementAvailable = true;
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
      managementAvailable = false;
      Logger.debug(logger, "Couldn't select Management application, use fallback");
    }

    int capabilities = 0;
    Integer serial = null;

    try {
      OtpData otpData = readOtpData(connection);
      capabilities |= Capability.OTP.bit;
      if (version == null) {
        version = otpData.version;
      }
      serial = otpData.serial;
    } catch (IOException e) {
      Logger.debug(logger, "Failure when selecting OTP application, serial unknown");
    } catch (ApplicationNotAvailableException e) {
      if (!managementAvailable) {
        // this is not a known YubiKey
        Logger.debug(logger, "Hardware key could not be identified");
        throw new IllegalArgumentException("Hardware key could not be identified");
      }
      Logger.debug(logger, "Couldn't select OTP application, serial unknown");
    }

    if (version == null) {
      Logger.debug(logger, "Firmware version unknown, using 3.0.0 as a baseline");
      version = new Version(3, 0, 0);
    }

    Logger.debug(logger, "Scan for available ccid applications");
    SmartCardProtocol protocol = new SmartCardProtocol(connection);
    for (final CcidApplet applet : CcidApplet.values()) {
      try {
        protocol.select(applet.aid);
        capabilities |= applet.capability.bit;
      } catch (ApplicationNotAvailableException applicationNotAvailableException) {
        Logger.debug(
            logger, "Missing applet {}, capability {}", applet.name(), applet.capability.name());
      } catch (IOException ioException) {
        Logger.warn(
            logger,
            "IOException selecting applet {}, capability {}",
            applet.name(),
            applet.capability.name(),
            ioException);
      }
    }

    if (((interfaces & UsbInterface.FIDO) != 0) || version.isAtLeast(3, 3, 0)) {
      capabilities |= Capability.U2F.bit;
    }

    Map<Transport, Integer> supportedCapabilities = new EnumMap<>(Transport.class);
    supportedCapabilities.put(Transport.USB, capabilities);
    supportedCapabilities.put(Transport.NFC, capabilities);

    return new DeviceInfo.Builder()
        .serialNumber(serial)
        .version(version)
        .supportedCapabilities(supportedCapabilities)
        .build();
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
          if (managementSession.supports(ManagementSession.FEATURE_DEVICE_INFO)) {
            return managementSession.getDeviceInfo();
          } else {
            otpSession = new YubiOtpSession(connection);
            serial = otpSession.getSerialNumber();
            break;
          }
        }
      } catch (CommandException commandException) {
        Logger.debug(logger, "Caught Command Exception", commandException);
        if (otpSession != null && interfaces == UsbInterface.OTP) {
          Logger.debug(logger, "This is not reclaim");
          break; // Can't be reclaim with only one interface
        }
        // can be caused by reclaim state
        try {
          Logger.debug(logger, "Potential reclaim, sleep...");
          Thread.sleep(500);
        } catch (InterruptedException ignored) {
          // ignoring interrupted exception
        }
      }
    }

    if (otpSession == null) {
      otpSession = new YubiOtpSession(connection);
    }

    version = otpSession.getVersion();
    int usbSupported;
    Map<Transport, Integer> capabilities = new EnumMap<>(Transport.class);

    if (keyType == YubiKeyType.NEO) {
      usbSupported = baseNeoApps;
      if ((interfaces & UsbInterface.FIDO) != 0 || version.isAtLeast(3, 0, 0)) {
        usbSupported |= Capability.U2F.bit;
      }
      capabilities.put(Transport.USB, usbSupported);
      capabilities.put(Transport.NFC, usbSupported);
    } else if (keyType == YubiKeyType.YKP) {
      capabilities.put(Transport.USB, Capability.OTP.bit | Capability.U2F.bit);
    } else {
      capabilities.put(Transport.USB, Capability.OTP.bit);
    }

    return new DeviceInfo.Builder()
        .serialNumber(serial)
        .version(version)
        .supportedCapabilities(capabilities)
        .build();
  }

  static DeviceInfo readInfoFido(FidoConnection connection, YubiKeyType keyType)
      throws IOException {
    try {
      ManagementSession session = new ManagementSession(connection);
      return session.getDeviceInfo();
    } catch (CommandException | UnsupportedOperationException exception) {
      Logger.debug(logger, "Unable to get info via Management application, using fallback");

      final Version version =
          keyType == YubiKeyType.YKP ? new Version(4, 0, 0) : new Version(3, 0, 0);

      Map<Transport, Integer> supportedApps = new EnumMap<>(Transport.class);
      supportedApps.put(Transport.USB, Capability.U2F.bit);
      if (keyType == YubiKeyType.NEO) {
        supportedApps.put(Transport.USB, Capability.U2F.bit | baseNeoApps);
        supportedApps.put(Transport.NFC, supportedApps.get(Transport.USB));
      }

      return new DeviceInfo.Builder()
          .version(version)
          .formFactor(FormFactor.USB_A_KEYCHAIN)
          .supportedCapabilities(supportedApps)
          .build();
    }
  }

  static boolean isPreviewVersion(Version version) {
    return (version.isAtLeast(5, 0, 0) && version.isLessThan(5, 1, 0))
        || (version.isAtLeast(5, 2, 0) && version.isLessThan(5, 2, 3))
        || (version.isAtLeast(5, 5, 0) && version.isLessThan(5, 5, 2));
  }

  /**
   * Reads out DeviceInfo from a YubiKey, or attempts to synthesize the data.
   *
   * <p>Reading DeviceInfo from a ManagementSession is only supported for newer YubiKeys. This
   * function attempts to read that information, but will fall back to gathering the data using
   * other mechanisms if needed. It will also make adjustments to the data if required, for example
   * to "fix" known bad values.
   *
   * <p>The <code>pid</code> parameter must be provided whenever the YubiKey is connected via USB,
   *
   * @param connection {@link SmartCardConnection}, {@link OtpConnection} or {@link FidoConnection}
   *     connection to the YubiKey
   * @param pid USB product ID of the YubiKey, can be null if unknown
   * @throws IOException in case of connection error
   * @throws IllegalArgumentException in case of <code>pid</code> is null for USB connection
   * @throws IllegalArgumentException in case of connection is not {@link SmartCardConnection},
   *     {@link OtpConnection} or {@link FidoConnection}
   * @throws IllegalArgumentException when the hardware key could not be identified
   */
  public static DeviceInfo readInfo(YubiKeyConnection connection, @Nullable UsbPid pid)
      throws IOException, IllegalArgumentException {

    YubiKeyType keyType = null;
    int interfaces = 0;

    if (pid != null) {
      keyType = pid.type;
      interfaces = pid.usbInterfaces;
    } else if (connection instanceof SmartCardConnection
        && ((SmartCardConnection) connection).getTransport() == Transport.NFC) {
      // For NEO we need to figure out the mode, newer keys get it from Management
      SmartCardProtocol protocol = new SmartCardProtocol(((SmartCardConnection) connection));
      try {
        byte[] response = protocol.select(AppId.OTP);
        if (response[0] == 3 && response.length > 6) {
          interfaces = UsbInterface.Mode.fromCode(response[6]).interfaces;
        }
      } catch (ApplicationNotAvailableException ignored) {
        // OTP turned off, this must be YK5
      }
    } else if (!(connection instanceof SmartCardConnection)
        || ((SmartCardConnection) connection).getTransport() == Transport.USB) {
      throw new IllegalArgumentException("pid missing for usb connection");
    }

    DeviceInfo info;
    if (connection instanceof SmartCardConnection) {
      info = readInfoCcid((SmartCardConnection) connection, interfaces);
    } else if (connection instanceof OtpConnection) {
      info = readInfoOtp((OtpConnection) connection, keyType, interfaces);
    } else if (connection instanceof FidoConnection) {
      info = readInfoFido((FidoConnection) connection, keyType);
    } else {
      throw new IllegalArgumentException("Invalid connection type");
    }

    Logger.debug(logger, "Read info {}", info);
    return adjustDeviceInfo(info, keyType, interfaces);
  }

  /**
   * This method adjusts the input DeviceInfo if required, for example it fixes known bad values.
   */
  static DeviceInfo adjustDeviceInfo(
      DeviceInfo info, @Nullable YubiKeyType keyType, int interfaces) {
    final DeviceConfig config = info.getConfig();
    final Version version =
        SessionVersionOverride.isDevelopmentVersion(info.getVersion())
            ? info.getVersionQualifier().getVersion()
            : info.getVersion();
    final FormFactor formFactor = info.getFormFactor();

    int supportedUsbCapabilities = info.getSupportedCapabilities(Transport.USB);
    int supportedNfcCapabilities = info.getSupportedCapabilities(Transport.NFC);

    Integer enabledUsbCapabilities = config.getEnabledCapabilities(Transport.USB);
    Integer enabledNfcCapabilities = config.getEnabledCapabilities(Transport.NFC);

    // Set usbEnabled if missing (pre YubiKey 5)
    if (info.hasTransport(Transport.USB) && enabledUsbCapabilities == null) {

      int usbEnabled = supportedUsbCapabilities;
      if (usbEnabled == (Capability.OTP.bit | Capability.U2F.bit | UsbInterface.CCID)) {
        // YubiKey Edge, hide unusable CCID interface from supported
        supportedUsbCapabilities = Capability.OTP.bit | Capability.U2F.bit;
      }

      if ((interfaces & UsbInterface.OTP) == 0) {
        usbEnabled &= ~Capability.OTP.bit;
      }

      if ((interfaces & UsbInterface.FIDO) == 0) {
        usbEnabled &= ~(Capability.U2F.bit | Capability.FIDO2.bit);
      }

      if ((interfaces & UsbInterface.CCID) == 0) {
        usbEnabled &=
            ~(UsbInterface.CCID
                | Capability.OATH.bit
                | Capability.OPENPGP.bit
                | Capability.PIV.bit);
      }

      enabledUsbCapabilities = usbEnabled;
    }

    final boolean isSky = info.isSky() || keyType == YubiKeyType.SKY;
    final boolean isFips =
        info.isFips() || (version.isAtLeast(4, 4, 0) && version.isLessThan(4, 5, 0));
    final boolean pinComplexity = info.getPinComplexity();

    // Set nfc_enabled if missing (pre YubiKey 5)
    if (info.hasTransport(Transport.NFC) && enabledNfcCapabilities == null) {
      enabledNfcCapabilities = supportedNfcCapabilities;
    }

    // Workaround for invalid configurations.
    if (version.isAtLeast(4, 0, 0)) {
      if (formFactor == FormFactor.USB_A_NANO
          || formFactor == FormFactor.USB_C_NANO
          || formFactor == FormFactor.USB_C_LIGHTNING
          || (formFactor == FormFactor.USB_C_KEYCHAIN && version.isLessThan(5, 2, 4))) {
        // Known not to have NFC
        supportedNfcCapabilities = 0;
        enabledNfcCapabilities = null;
      }
    }

    final Integer deviceFlags = config.getDeviceFlags();
    final Short autoEjectTimeout = config.getAutoEjectTimeout();
    final Byte challengeResponseTimeout = config.getChallengeResponseTimeout();
    final Boolean isNfcRestricted = config.getNfcRestricted();

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

    configBuilder.nfcRestricted(isNfcRestricted);

    Map<Transport, Integer> capabilities = new EnumMap<>(Transport.class);
    if (supportedUsbCapabilities != 0) {
      capabilities.put(Transport.USB, supportedUsbCapabilities);
    }
    if (supportedNfcCapabilities != 0) {
      capabilities.put(Transport.NFC, supportedNfcCapabilities);
    }

    return new DeviceInfo.Builder()
        .config(configBuilder.build())
        .version(version)
        .versionQualifier(info.getVersionQualifier())
        .formFactor(formFactor)
        .serialNumber(info.getSerialNumber())
        .supportedCapabilities(capabilities)
        .isLocked(info.isLocked())
        .isFips(isFips)
        .isSky(isSky)
        .partNumber(info.getPartNumber())
        .fipsCapable(info.getFipsCapable())
        .fipsApproved(info.getFipsApproved())
        .pinComplexity(pinComplexity)
        .resetBlocked(info.getResetBlocked())
        .fpsVersion(info.getFpsVersion())
        .stmVersion(info.getStmVersion())
        .build();
  }

  /** Determine the product name of a YubiKey */
  public static String getName(DeviceInfo info, @Nullable YubiKeyType keyType) {

    final Version version = info.getVersion();
    final FormFactor formFactor = info.getFormFactor();

    final int supportedUsbCapabilities = info.getSupportedCapabilities(Transport.USB);
    final boolean isFidoOnly =
        (supportedUsbCapabilities & ~(Capability.U2F.bit | Capability.FIDO2.bit)) == 0;

    final YubiKeyType yubiKeyType =
        keyType != null
            ? keyType
            : (info.getSerialNumber() == null && isFidoOnly)
                ? YubiKeyType.SKY
                : (version.major == 3) ? YubiKeyType.NEO : YubiKeyType.YK4;

    String deviceName = yubiKeyType.name;

    if (yubiKeyType == YubiKeyType.SKY) {
      if ((supportedUsbCapabilities & Capability.FIDO2.bit) == Capability.FIDO2.bit) {
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
          // YK4 FIPS
          deviceName = "YubiKey FIPS";
        } else if (supportedUsbCapabilities == (Capability.OTP.bit | Capability.U2F.bit)) {
          deviceName = "YubiKey Edge";
        } else {
          deviceName = "YubiKey 4";
        }
      }
    }

    if (isPreviewVersion(version)) {
      deviceName = "YubiKey Preview";
    } else if (version.isAtLeast(5, 1, 0)) {
      boolean isNano = formFactor == FormFactor.USB_A_NANO || formFactor == FormFactor.USB_C_NANO;
      boolean isBio = formFactor == FormFactor.USB_A_BIO || formFactor == FormFactor.USB_C_BIO;
      // does not include Ci
      boolean isC =
          formFactor == FormFactor.USB_C_KEYCHAIN
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
        } else if ((supportedUsbCapabilities & Capability.PIV.bit) == Capability.PIV.bit) {
          namePartsList.add("- Multi-protocol Edition");
        }
      } else if (info.isFips()) {
        namePartsList.add("FIPS");
      } else if (info.isSky() && info.getSerialNumber() != null) {
        namePartsList.add("- Enterprise Edition");
      } else if (info.getPinComplexity() && !info.isSky()) {
        namePartsList.add("- Enhanced PIN");
      }

      StringBuilder builder = new StringBuilder();
      for (int partCount = 0; partCount < namePartsList.size(); partCount++) {
        String s = namePartsList.get(partCount);
        builder.append(s);
        if (partCount < namePartsList.size() - 1) {
          builder.append(" ");
        }
      }
      deviceName = builder.toString().replace("5 C", "5C").replace("5 A", "5A");
    }
    return deviceName;
  }

  // Applet and capability it provides
  enum CcidApplet {
    OPENPGP(AppId.OPENPGP, Capability.OPENPGP),
    OATH(AppId.OATH, Capability.OATH),
    PIV(AppId.PIV, Capability.PIV),
    FIDO(AppId.FIDO, Capability.U2F),
    AID_U2F_YUBICO(
        new byte[] {(byte) 0xa0, 0x00, 0x00, 0x05, 0x27, 0x10, 0x02},
        Capability.U2F); // Old U2F AID

    public final byte[] aid;
    public final Capability capability;

    CcidApplet(byte[] aid, Capability capability) {
      this.aid = aid;
      this.capability = capability;
    }
  }
}

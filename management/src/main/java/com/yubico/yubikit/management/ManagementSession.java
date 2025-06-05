/*
 * Copyright (C) 2019-2025 Yubico.
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

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbInterface;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.ApplicationSession;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.application.Feature;
import com.yubico.yubikit.core.application.SessionVersionOverride;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.fido.FidoProtocol;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.otp.ChecksumUtils;
import com.yubico.yubikit.core.otp.OtpConnection;
import com.yubico.yubikit.core.otp.OtpProtocol;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import com.yubico.yubikit.core.util.Tlvs;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

/**
 * Application to get information about and configure a YubiKey via the Management Application.
 *
 * @see <a href="https://developers.yubico.com/yubikey-manager/Config_Reference.html">
 *     https://developers.yubico.com/yubikey-manager/Config_Reference.html</a>
 */
public class ManagementSession extends ApplicationSession<ManagementSession> {
  // Features
  /** Support the SET_MODE command to change the USB mode of the YubiKey. */
  public static final Feature<ManagementSession> FEATURE_MODE =
      new Feature<ManagementSession>("Mode") {
        @Override
        public boolean isSupportedBy(Version version) {
          return version.isAtLeast(3, 0, 0) && version.isLessThan(5, 0, 0);
        }
      };

  /** Support for reading the DeviceInfo data from the YubiKey. */
  public static final Feature<ManagementSession> FEATURE_DEVICE_INFO =
      new Feature.Versioned<>("Device Info", 4, 1, 0);

  /** Support for writing DeviceConfig data to the YubiKey. */
  public static final Feature<ManagementSession> FEATURE_DEVICE_CONFIG =
      new Feature.Versioned<>("Device Config", 5, 0, 0);

  /** Support for device-wide reset. */
  public static final Feature<ManagementSession> FEATURE_DEVICE_RESET =
      new Feature.Versioned<>("Device Reset", 5, 6, 0);

  // Smart card command constants
  private static final byte OTP_INS_CONFIG = 0x01;
  private static final byte INS_READ_CONFIG = 0x1d;
  private static final byte INS_WRITE_CONFIG = 0x1c;
  private static final byte INS_SET_MODE = 0x16;
  private static final byte INS_DEVICE_RESET = 0x1f;
  private static final byte P1_DEVICE_CONFIG = 0x11;

  // OTP command constants
  private static final byte CMD_DEVICE_CONFIG = 0x11;
  private static final byte CMD_YK4_CAPABILITIES = 0x13;
  private static final byte CMD_YK4_SET_DEVICE_INFO = 0x15;

  // FIDO command constants
  private static final byte CTAP_TYPE_INIT = (byte) 0x80;
  private static final byte CTAP_VENDOR_FIRST = 0x40;
  private static final byte CTAP_YUBIKEY_DEVICE_CONFIG = CTAP_TYPE_INIT | CTAP_VENDOR_FIRST;
  private static final byte CTAP_READ_CONFIG = CTAP_TYPE_INIT | CTAP_VENDOR_FIRST + 2;
  private static final byte CTAP_WRITE_CONFIG = CTAP_TYPE_INIT | CTAP_VENDOR_FIRST + 3;

  private final Backend<?> backend;
  private final Version version;

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(ManagementSession.class);

  /**
   * Establishes a new session with a YubiKeys Management application, over a {@link
   * SmartCardConnection}.
   *
   * @param connection connection with YubiKey
   * @throws IOException in case of connection error
   * @throws ApplicationNotAvailableException in case the application is missing/disabled
   */
  public ManagementSession(SmartCardConnection connection)
      throws IOException, ApplicationNotAvailableException {
    this(connection, null);
  }

  /**
   * Establishes a new session with a YubiKeys Management application, over a {@link
   * SmartCardConnection}.
   *
   * @param connection connection with YubiKey
   * @param scpKeyParams SCP key parameters to establish a secure connection
   * @throws IOException in case of connection error
   * @throws ApplicationNotAvailableException in case the application is missing/disabled
   */
  public ManagementSession(SmartCardConnection connection, @Nullable ScpKeyParams scpKeyParams)
      throws IOException, ApplicationNotAvailableException {
    SmartCardProtocol protocol = new SmartCardProtocol(connection);
    Version version;
    try {
      version =
          Version.parse(new String(protocol.select(AppId.MANAGEMENT), StandardCharsets.UTF_8));
      if (scpKeyParams != null) {
        protocol.initScp(scpKeyParams);
      } else if (version.major == 3) {
        // Workaround to "de-select" on NEO
        connection.sendAndReceive(new byte[] {(byte) 0xa4, 0x04, 0x00, 0x08});
        protocol.select(AppId.OTP);
      }
    } catch (ApplicationNotAvailableException e) {
      if (connection.getTransport() == Transport.NFC) {
        // NEO doesn't support the Management Application over NFC, but can use the OTP application.
        version = Version.fromBytes(protocol.select(AppId.OTP));
      } else {
        throw e;
      }
    } catch (BadResponseException | ApduException e) {
      throw new IOException("Failed setting up SCP session", e);
    }

    if (version.major == 3) { // NEO, using the OTP application
      backend =
          new Backend<SmartCardProtocol>(protocol) {
            @Override
            byte[] readConfig(int page) {
              throw new UnsupportedOperationException("readConfig not supported on YubiKey NEO");
            }

            @Override
            void writeConfig(byte[] config) {
              throw new UnsupportedOperationException("writeConfig not supported on YubiKey NEO");
            }

            @Override
            void setMode(byte[] data) throws IOException, CommandException {
              delegate.sendAndReceive(new Apdu(0, OTP_INS_CONFIG, CMD_DEVICE_CONFIG, 0, data));
            }

            @Override
            void deviceReset() {
              throw new UnsupportedOperationException("deviceReset not supported on YubiKey NEO");
            }
          };
    } else {
      backend =
          new Backend<SmartCardProtocol>(protocol) {
            @Override
            byte[] readConfig(int page) throws IOException, CommandException {
              Logger.debug(logger, "Reading config page {}...", page);
              return delegate.sendAndReceive(new Apdu(0, INS_READ_CONFIG, page, 0, null));
            }

            @Override
            void writeConfig(byte[] config) throws IOException, CommandException {
              delegate.sendAndReceive(new Apdu(0, INS_WRITE_CONFIG, 0, 0, config));
            }

            @Override
            void setMode(byte[] data) throws IOException, CommandException {
              delegate.sendAndReceive(new Apdu(0, INS_SET_MODE, P1_DEVICE_CONFIG, 0, data));
            }

            @Override
            void deviceReset() throws IOException, CommandException {
              delegate.sendAndReceive(new Apdu(0, INS_DEVICE_RESET, 0, 0, null));
            }
          };
    }
    this.version = getQualifiedVersion(version);
    protocol.configure(version);
    logCtor(connection);
  }

  /**
   * Establishes a new session with a YubiKeys Management application, over an {@link
   * OtpConnection}.
   *
   * @param connection connection with YubiKey
   * @throws IOException in case of connection error
   * @throws ApplicationNotAvailableException in case the application is missing/disabled
   */
  public ManagementSession(OtpConnection connection)
      throws IOException, ApplicationNotAvailableException {
    OtpProtocol protocol = new OtpProtocol(connection);
    Version version = Version.fromBytes(protocol.readStatus());
    if (version.isLessThan(3, 0, 0) && version.major != 0) {
      throw new ApplicationNotAvailableException(
          "Management Application requires YubiKey 3 or later");
    }
    backend =
        new Backend<OtpProtocol>(protocol) {
          @Override
          byte[] readConfig(int page) throws IOException, CommandException {
            Logger.debug(logger, "Reading config page {}...", page);
            byte[] response =
                delegate.sendAndReceive(CMD_YK4_CAPABILITIES, pagePayload(page), null);
            if (ChecksumUtils.checkCrc(response, response[0] + 1 + 2)) {
              return Arrays.copyOf(response, response[0] + 1);
            }
            throw new IOException("Invalid CRC");
          }

          @Override
          void writeConfig(byte[] config) throws IOException, CommandException {
            delegate.sendAndReceive(CMD_YK4_SET_DEVICE_INFO, config, null);
          }

          @Override
          void setMode(byte[] data) throws IOException, CommandException {
            delegate.sendAndReceive(CMD_DEVICE_CONFIG, data, null);
          }

          @Override
          void deviceReset() {
            throw new UnsupportedOperationException("deviceReset is only available over CCID");
          }
        };
    this.version = getQualifiedVersion(version);
    logCtor(connection);
  }

  /**
   * Establishes a new session with a YubiKeys Management application, over a {@link
   * FidoConnection}.
   *
   * @param connection a connection over the FIDO USB transport with a YubiKey
   * @throws IOException in case of connection error
   */
  public ManagementSession(FidoConnection connection) throws IOException {
    FidoProtocol protocol = new FidoProtocol(connection);
    Version version = protocol.getVersion();
    if (version.major < 4) {
      // Prior to YK4 this was not firmware version
      if (!(version.major == 0 && protocol.supports(FidoProtocol.Capability.CBOR))) {
        version = new Version(3, 0, 0);
      }
    }

    backend =
        new Backend<FidoProtocol>(protocol) {
          @Override
          byte[] readConfig(int page) throws IOException {
            Logger.debug(logger, "Reading config page {}...", page);
            return delegate.sendAndReceive(CTAP_READ_CONFIG, pagePayload(page), null);
          }

          @Override
          void writeConfig(byte[] config) throws IOException {
            delegate.sendAndReceive(CTAP_WRITE_CONFIG, config, null);
          }

          @Override
          void setMode(byte[] data) throws IOException {
            delegate.sendAndReceive(CTAP_YUBIKEY_DEVICE_CONFIG, data, null);
          }

          @Override
          void deviceReset() {
            throw new UnsupportedOperationException("deviceReset is only available over CCID");
          }
        };
    this.version = getQualifiedVersion(version);
    logCtor(connection);
  }

  /**
   * Connects to a YubiKeyDevice and establishes a new session with a YubiKeys Management
   * application.
   *
   * <p>This method will use whichever connection type is available.
   *
   * @param device A YubiKey device to use
   */
  public static void create(
      YubiKeyDevice device, Callback<Result<ManagementSession, Exception>> callback) {
    if (device.supportsConnection(SmartCardConnection.class)) {
      device.requestConnection(
          SmartCardConnection.class,
          value -> callback.invoke(Result.of(() -> new ManagementSession(value.getValue()))));
    } else if (device.supportsConnection(OtpConnection.class)) {
      device.requestConnection(
          OtpConnection.class,
          value -> callback.invoke(Result.of(() -> new ManagementSession(value.getValue()))));
    } else if (device.supportsConnection(FidoConnection.class)) {
      device.requestConnection(
          FidoConnection.class,
          value -> callback.invoke(Result.of(() -> new ManagementSession(value.getValue()))));
    } else {
      callback.invoke(
          Result.failure(
              new ApplicationNotAvailableException(
                  "Session does not support any compatible connection type")));
    }
  }

  @Override
  public void close() throws IOException {
    backend.close();
  }

  @Override
  public Version getVersion() {
    return version;
  }

  /**
   * Get device information from the YubiKey.
   *
   * <p>This functionality requires support for {@link #FEATURE_DEVICE_INFO}, available on YubiKey
   * 4.1 or later.
   *
   * @return a DeviceInfo object
   * @throws IOException in case of connection error
   * @throws CommandException in case of error response
   */
  public DeviceInfo getDeviceInfo() throws IOException, CommandException {
    require(FEATURE_DEVICE_INFO);
    return readDeviceInfo();
  }

  /**
   * Get device information from the YubiKey.
   *
   * @return a DeviceInfo object
   * @throws IOException in case of connection error
   * @throws CommandException in case of error response
   */
  private DeviceInfo readDeviceInfo() throws IOException, CommandException {
    final Map<Integer, byte[]> tlvs = new HashMap<>();
    boolean hasMoreData = true;
    int page = 0;

    while (hasMoreData) {
      final byte[] encoded = backend.readConfig(page);
      if (encoded.length - 1 != encoded[0]) {
        throw new BadResponseException("Invalid length");
      }
      Map<Integer, byte[]> decoded = Tlvs.decodeMap(Arrays.copyOfRange(encoded, 1, encoded.length));
      byte[] moreData = decoded.get(0x10); // YK_MORE_DEVICE_INFO
      hasMoreData = moreData != null && moreData.length == 1 && moreData[0] == (byte) 1;
      tlvs.putAll(decoded);
      page++;
    }
    return DeviceInfo.parseTlvs(tlvs, version);
  }

  /**
   * Write device configuration to a YubiKey 5 or later.
   *
   * <p>This functionality requires support for {@link #FEATURE_DEVICE_CONFIG}, available on YubiKey
   * 5 or later.
   *
   * @param config the device configuration to write
   * @param reboot if true cause the YubiKey to immediately reboot, applying the new configuration
   * @param currentLockCode required if a configuration lock code is set
   * @param newLockCode changes or removes (if 16 byte all-zero) the configuration lock code
   * @throws IOException in case of connection error
   * @throws CommandException in case of error response
   */
  public void updateDeviceConfig(
      DeviceConfig config,
      boolean reboot,
      @Nullable byte[] currentLockCode,
      @Nullable byte[] newLockCode)
      throws IOException, CommandException {
    require(FEATURE_DEVICE_CONFIG);
    byte[] data = config.getBytes(reboot, currentLockCode, newLockCode);
    Logger.debug(
        logger,
        "Writing device config: {}, reboot: {}, " + "current lock code: {}, new lock code: {}",
        config,
        reboot,
        currentLockCode != null,
        newLockCode != null);
    backend.writeConfig(data);
    Logger.info(logger, "Device config written");
  }

  /**
   * Write device configuration for YubiKey NEO and YubiKey 4.
   *
   * <p>This functionality requires support for {@link #FEATURE_MODE}, available on YubiKey 3 and 4.
   * If {@link #FEATURE_DEVICE_CONFIG} is supported, the mode will be translated into a DeviceConfig
   * and {@link #updateDeviceConfig} will instead be used.
   *
   * @param mode USB transport mode to set
   * @param chalrespTimeout timeout (seconds) for challenge-response requiring touch.
   * @param autoejectTimeout timeout (10x seconds) for auto-eject (only used for CCID-only mode).
   * @throws IOException in case of connection error
   * @throws ApduException in case of communication or not supported operation error
   */
  public void setMode(UsbInterface.Mode mode, byte chalrespTimeout, short autoejectTimeout)
      throws IOException, CommandException {
    Logger.debug(
        logger,
        "Set mode: {}, chalresp_timeout: {}, auto_eject_timeout: {}",
        mode,
        chalrespTimeout,
        autoejectTimeout);
    if (supports(FEATURE_DEVICE_CONFIG)) {
      // Translate into DeviceConfig and set using writeDeviceConfig
      int usbEnabled = 0;
      if ((mode.interfaces & UsbInterface.OTP) != 0) {
        usbEnabled |= Capability.OTP.bit;
      }
      if ((mode.interfaces & UsbInterface.CCID) != 0) {
        usbEnabled |= Capability.OATH.bit | Capability.PIV.bit | Capability.OPENPGP.bit;
      }
      if ((mode.interfaces & UsbInterface.FIDO) != 0) {
        usbEnabled |= Capability.U2F.bit | Capability.FIDO2.bit;
      }
      Logger.debug(logger, "Delegating to DeviceConfig with usb_enabled: {}", usbEnabled);
      updateDeviceConfig(
          new DeviceConfig.Builder()
              .enabledCapabilities(Transport.USB, usbEnabled)
              .challengeResponseTimeout(chalrespTimeout)
              .autoEjectTimeout(autoejectTimeout)
              .build(),
          false,
          null,
          null);
    } else {
      require(FEATURE_MODE);
      byte[] data =
          ByteBuffer.allocate(4)
              .put(mode.value)
              .put(chalrespTimeout)
              .putShort(autoejectTimeout)
              .array();
      backend.setMode(data);
      Logger.info(logger, "Mode configuration written");
    }
  }

  /**
   * Perform a device-wide reset in Bio Multi-protocol Edition devices.
   *
   * <p>This functionality requires support for {@link #FEATURE_DEVICE_RESET}.
   *
   * @throws IOException in case of connection error
   * @throws ApduException in case of communication or not supported operation error
   */
  public void deviceReset() throws IOException, CommandException {
    require(FEATURE_DEVICE_RESET);
    backend.deviceReset();
    Logger.info(logger, "Device reset");
  }

  private abstract static class Backend<T extends Closeable> implements Closeable {
    protected final T delegate;

    private Backend(T delegate) {
      this.delegate = delegate;
    }

    byte[] readConfig() throws IOException, CommandException {
      return readConfig(0);
    }

    abstract byte[] readConfig(int page) throws IOException, CommandException;

    abstract void writeConfig(byte[] config) throws IOException, CommandException;

    abstract void setMode(byte[] data) throws IOException, CommandException;

    abstract void deviceReset() throws IOException, CommandException;

    @Override
    public void close() throws IOException {
      delegate.close();
    }
  }

  private void logCtor(YubiKeyConnection connection) {
    Logger.debug(
        logger,
        "Management session initialized for connection={}, version={}",
        connection.getClass().getSimpleName(),
        getVersion());
  }

  private static byte[] pagePayload(int page) {
    if (page > 255 || page < 0) {
      throw new IllegalArgumentException("Invalid page value " + page);
    }
    return new byte[] {(byte) page};
  }

  /**
   * Retrieves the versionQualifier version of the YubiKey device.
   *
   * <p>If the provided version is identified as a development version, this method overrides it by
   * with version from the versionQualifier.
   *
   * @param version the initial version of the YubiKey device.
   * @return the version override.
   * @throws IOException if reading the device information fails.
   */
  private Version getQualifiedVersion(Version version) throws IOException {
    if (!SessionVersionOverride.isDevelopmentVersion(version)) {
      return version;
    }
    try {
      logger.debug("Overriding development version...");
      Version result = readDeviceInfo().getVersionQualifier().getVersion();
      SessionVersionOverride.set(result);
      return result;
    } catch (CommandException e) {
      // failed to read device info where it was expected
      throw new IOException("Failed reading device info.", e);
    }
  }
}

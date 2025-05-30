/*
 * Copyright (C) 2020-2022,2024 Yubico.
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
import com.yubico.yubikit.core.util.Tlvs;
import java.nio.ByteBuffer;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

/** Describes the configuration of a YubiKey which can be altered via the Management application. */
public class DeviceConfig {
  /** In pure CCID mode eject/inject the card with the button. */
  public static final int FLAG_EJECT = 0x80;

  /** Enables remote wakeup. */
  public static final int FLAG_REMOTE_WAKEUP = 0x40;

  private static final int TAG_USB_ENABLED = 0x03;
  private static final int TAG_AUTO_EJECT_TIMEOUT = 0x06;
  private static final int TAG_CHALLENGE_RESPONSE_TIMEOUT = 0x07;
  private static final int TAG_DEVICE_FLAGS = 0x08;
  private static final int TAG_NFC_ENABLED = 0x0e;
  private static final int TAG_CONFIGURATION_LOCK = 0x0a;
  private static final int TAG_UNLOCK = 0x0b;
  private static final int TAG_REBOOT = 0x0c;
  private static final int TAG_NFC_RESTRICTED = 0x17;

  private final Map<Transport, Integer> enabledCapabilities;
  @Nullable private final Short autoEjectTimeout;
  @Nullable private final Byte challengeResponseTimeout;
  @Nullable private final Integer deviceFlags;
  @Nullable private final Boolean nfcRestricted;

  @Deprecated
  DeviceConfig(
      Map<Transport, Integer> enabledCapabilities,
      @Nullable Short autoEjectTimeout,
      @Nullable Byte challengeResponseTimeout,
      @Nullable Integer deviceFlags) {
    this.enabledCapabilities = enabledCapabilities;
    this.autoEjectTimeout = autoEjectTimeout;
    this.challengeResponseTimeout = challengeResponseTimeout;
    this.deviceFlags = deviceFlags;
    this.nfcRestricted = null;
  }

  DeviceConfig(Builder builder) {
    this.enabledCapabilities = builder.enabledCapabilities;
    this.autoEjectTimeout = builder.autoEjectTimeout;
    this.challengeResponseTimeout = builder.challengeResponseTimeout;
    this.deviceFlags = builder.deviceFlags;
    this.nfcRestricted = builder.nfcRestricted;
  }

  /**
   * Get the currently enabled capabilities for a given Interface.
   *
   * <p>NOTE: This method will return null if the Interface is not supported by the YubiKey, OR if
   * the enabled capabilities state isn't readable. The YubiKey 4 series, for example, does not
   * return enabled-status for USB applications.
   *
   * @param transport the physical transport to get enabled capabilities for
   * @return the enabled capabilities, represented as {@link Capability} bits being set (1) or not
   *     (0)
   */
  @Nullable
  public Integer getEnabledCapabilities(Transport transport) {
    return enabledCapabilities.get(transport);
  }

  /** Returns the timeout used when in CCID-only mode with {@link #FLAG_EJECT} enabled. */
  @Nullable
  public Short getAutoEjectTimeout() {
    return autoEjectTimeout;
  }

  /**
   * Returns the timeout value used by the YubiOTP application when waiting for a user presence
   * check (physical touch).
   */
  @Nullable
  public Byte getChallengeResponseTimeout() {
    return challengeResponseTimeout;
  }

  /** Returns the NFC restricted flag. */
  @Nullable
  public Boolean getNfcRestricted() {
    return nfcRestricted;
  }

  /** Returns the device flags that are set. */
  @Nullable
  public Integer getDeviceFlags() {
    return deviceFlags;
  }

  byte[] getBytes(boolean reboot, @Nullable byte[] currentLockCode, @Nullable byte[] newLockCode) {
    Map<Integer, byte[]> values = new LinkedHashMap<>();
    if (reboot) {
      values.put(TAG_REBOOT, null);
    }
    if (currentLockCode != null) {
      values.put(TAG_UNLOCK, currentLockCode);
    }
    Integer usbEnabled = enabledCapabilities.get(Transport.USB);
    if (usbEnabled != null) {
      values.put(TAG_USB_ENABLED, new byte[] {(byte) (usbEnabled >> 8), usbEnabled.byteValue()});
    }
    Integer nfcEnabled = enabledCapabilities.get(Transport.NFC);
    if (nfcEnabled != null) {
      values.put(TAG_NFC_ENABLED, new byte[] {(byte) (nfcEnabled >> 8), nfcEnabled.byteValue()});
    }
    if (autoEjectTimeout != null) {
      values.put(
          TAG_AUTO_EJECT_TIMEOUT,
          new byte[] {(byte) (autoEjectTimeout >> 8), autoEjectTimeout.byteValue()});
    }
    if (challengeResponseTimeout != null) {
      values.put(TAG_CHALLENGE_RESPONSE_TIMEOUT, new byte[] {challengeResponseTimeout});
    }
    if (deviceFlags != null) {
      values.put(TAG_DEVICE_FLAGS, new byte[] {deviceFlags.byteValue()});
    }
    if (newLockCode != null) {
      values.put(TAG_CONFIGURATION_LOCK, newLockCode);
    }
    if (nfcRestricted != null) {
      values.put(TAG_NFC_RESTRICTED, new byte[] {nfcRestricted ? 0x01 : (byte) 0x00});
    }
    byte[] data = Tlvs.encodeMap(values);

    if (data.length > 0xff) {
      throw new IllegalStateException("DeviceConfiguration too large");
    }
    return ByteBuffer.allocate(data.length + 1).put((byte) data.length).put(data).array();
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    DeviceConfig that = (DeviceConfig) o;
    return Objects.equals(enabledCapabilities, that.enabledCapabilities)
        && Objects.equals(autoEjectTimeout, that.autoEjectTimeout)
        && Objects.equals(challengeResponseTimeout, that.challengeResponseTimeout)
        && Objects.equals(deviceFlags, that.deviceFlags)
        && Objects.equals(nfcRestricted, that.nfcRestricted);
  }

  @Override
  public int hashCode() {
    return Objects.hash(
        enabledCapabilities,
        autoEjectTimeout,
        challengeResponseTimeout,
        deviceFlags,
        nfcRestricted);
  }

  /**
   * Builder class for use with {@link ManagementSession#updateDeviceConfig} when altering the
   * device configuration.
   */
  public static class Builder {
    private final Map<Transport, Integer> enabledCapabilities = new HashMap<>();
    @Nullable private Short autoEjectTimeout;
    @Nullable private Byte challengeResponseTimeout;
    @Nullable private Integer deviceFlags;
    @Nullable private Boolean nfcRestricted;

    /**
     * Sets the enabled capabilities for the given transport.
     *
     * @param transport the transport to change capabilities for
     * @param capabilities the capabilities to set
     */
    public Builder enabledCapabilities(Transport transport, int capabilities) {
      enabledCapabilities.put(transport, capabilities);
      return this;
    }

    /**
     * Sets the timeout used when the YubiKey is in CCID-only mode with {@link #FLAG_EJECT} set.
     *
     * @param autoEjectTimeout the timeout, in seconds
     */
    public Builder autoEjectTimeout(short autoEjectTimeout) {
      this.autoEjectTimeout = autoEjectTimeout;
      return this;
    }

    /**
     * Sets the timeout used by the YubiOTP application, when waiting for a user presence check
     * (physical touch).
     *
     * @param challengeResponseTimeout the timeout, in seconds
     */
    public Builder challengeResponseTimeout(byte challengeResponseTimeout) {
      this.challengeResponseTimeout = challengeResponseTimeout;
      return this;
    }

    /** Sets the Device flags of the YubiKey. */
    public Builder deviceFlags(int deviceFlags) {
      this.deviceFlags = deviceFlags;
      return this;
    }

    /** Sets the NFC restricted flag of the YubiKey. */
    public Builder nfcRestricted(@Nullable Boolean nfcRestricted) {
      this.nfcRestricted = nfcRestricted;
      return this;
    }

    /** Constructs a DeviceConfig using the current configuration. */
    public DeviceConfig build() {
      return new DeviceConfig(this);
    }
  }

  @Override
  public String toString() {
    return "DeviceConfig{"
        + "enabledCapabilities="
        + enabledCapabilities
        + ", autoEjectTimeout="
        + autoEjectTimeout
        + ", challengeResponseTimeout="
        + challengeResponseTimeout
        + ", deviceFlags="
        + deviceFlags
        + ", nfcRestricted="
        + nfcRestricted
        + '}';
  }
}

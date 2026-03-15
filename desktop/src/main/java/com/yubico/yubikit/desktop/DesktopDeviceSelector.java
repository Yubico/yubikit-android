/*
 * Copyright (C) 2026 Yubico.
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
package com.yubico.yubikit.desktop;

import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Identifies a specific YubiKey device for selection purposes.
 *
 * <p>A selector can target a device either by its <strong>serial number</strong> (preferred when
 * available) or by its <strong>fingerprint</strong> (a fallback identifier derived from the
 * underlying USB device path or PCSC terminal name).
 *
 * <p><strong>Serial number selection</strong> is preferred because serial numbers are stable across
 * unplug/replug cycles and across processes. Use {@link #forSerial(int)} when the device serial is
 * known.
 *
 * <p><strong>Fingerprint selection</strong> is a fallback for devices that do not expose a serial
 * number (e.g. certain Security Key models). Note that fingerprints are <em>not</em> guaranteed to
 * be stable across unplug/replug cycles or across process restarts — they are derived from
 * OS-assigned device paths. Use {@link #forFingerprint(String)} when serial is unavailable.
 *
 * @see DesktopDeviceRecord
 * @see YubiKitManager#listDeviceRecords()
 */
public final class DesktopDeviceSelector {

  private final @Nullable Integer serial;
  private final @Nullable String fingerprint;

  private DesktopDeviceSelector(@Nullable Integer serial, @Nullable String fingerprint) {
    if (serial == null && fingerprint == null) {
      throw new IllegalArgumentException("Either serial or fingerprint must be provided");
    }
    this.serial = serial;
    this.fingerprint = fingerprint;
  }

  /**
   * Creates a selector that targets a device by its serial number.
   *
   * @param serial the device serial number
   * @return a serial-based selector
   */
  public static DesktopDeviceSelector forSerial(int serial) {
    return new DesktopDeviceSelector(serial, null);
  }

  /**
   * Creates a selector that targets a device by its fingerprint.
   *
   * <p>The fingerprint is typically the HID device path or PCSC terminal name. It is <em>not</em>
   * guaranteed to be stable across unplug/replug cycles or process restarts.
   *
   * @param fingerprint the device fingerprint
   * @return a fingerprint-based selector
   */
  public static DesktopDeviceSelector forFingerprint(String fingerprint) {
    return new DesktopDeviceSelector(null, fingerprint);
  }

  /**
   * Returns the serial number used for selection, or {@code null} if this selector uses a
   * fingerprint.
   */
  public @Nullable Integer getSerial() {
    return serial;
  }

  /**
   * Returns the fingerprint used for selection, or {@code null} if this selector uses a serial
   * number.
   */
  public @Nullable String getFingerprint() {
    return fingerprint;
  }

  @Override
  public boolean equals(@Nullable Object o) {
    if (this == o) return true;
    if (!(o instanceof DesktopDeviceSelector)) return false;
    DesktopDeviceSelector that = (DesktopDeviceSelector) o;
    if (!Objects.equals(serial, that.serial)) return false;
    return Objects.equals(fingerprint, that.fingerprint);
  }

  @Override
  public int hashCode() {
    int result = serial != null ? serial.hashCode() : 0;
    result = 31 * result + (fingerprint != null ? fingerprint.hashCode() : 0);
    return result;
  }

  @Override
  public String toString() {
    if (serial != null) {
      return "DesktopDeviceSelector{serial=" + serial + "}";
    }
    return "DesktopDeviceSelector{fingerprint='" + fingerprint + "'}";
  }
}

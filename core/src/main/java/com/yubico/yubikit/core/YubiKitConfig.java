/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.core;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Configuration class for YubiKit core application.
 *
 * <p>This class manages configuration options, such as enabling support for other vendors. Use the
 * nested {@link Builder} to construct instances with custom settings.
 */
public final class YubiKitConfig {

  /**
   * The default configuration instance for YubiKit.
   *
   * <p>By default, support for other vendors is disabled.
   */
  public static final YubiKitConfig DEFAULT =
      new YubiKitConfig.Builder().setSupportOtherVendors(false).build();

  /**
   * Holds the current singleton instance of {@link YubiKitConfig}.
   *
   * <p>Use {@link #get()} and {@link #set(YubiKitConfig)} to access or modify the instance.
   */
  private static final AtomicReference<YubiKitConfig> instance = new AtomicReference<>(DEFAULT);

  /**
   * Builder for {@link YubiKitConfig}.
   *
   * <p>Allows configuration of YubiKit options before creating an instance.
   */
  public static class Builder {
    private boolean supportOtherVendors = false;

    /**
     * Sets whether support for other vendors is enabled.
     *
     * @param value true to enable support for other vendors, false to disable
     * @return this builder instance
     */
    public Builder setSupportOtherVendors(boolean value) {
      this.supportOtherVendors = value;
      return this;
    }

    /**
     * Builds a {@link YubiKitConfig} instance with the specified options.
     *
     * @return a configured {@link YubiKitConfig} instance
     */
    public YubiKitConfig build() {
      return new YubiKitConfig(this.supportOtherVendors);
    }
  }

  /** Indicates whether support for other vendors is enabled. */
  private final boolean supportOtherVendors;

  private YubiKitConfig(boolean supportOtherVendors) {
    this.supportOtherVendors = supportOtherVendors;
  }

  /**
   * Returns the current singleton instance of {@link YubiKitConfig}.
   *
   * <p>If not set, returns {@link #DEFAULT}.
   *
   * @return the current {@link YubiKitConfig} instance
   */
  public static YubiKitConfig get() {
    return instance.get();
  }

  /**
   * Sets the singleton instance of {@link YubiKitConfig}.
   *
   * <p>This will replace the current configuration globally.
   *
   * @param config the new {@link YubiKitConfig} instance to set
   */
  public static void set(YubiKitConfig config) {
    instance.set(config);
  }

  /**
   * Copy constructor for {@link YubiKitConfig}.
   *
   * <p>Creates a new instance with the same configuration as the provided instance.
   *
   * @param other the {@link YubiKitConfig} instance to copy from
   */
  private YubiKitConfig(YubiKitConfig other) {
    this.supportOtherVendors = other.supportOtherVendors;
  }

  public static boolean isSupportOtherVendors() {
    return get().supportOtherVendors;
  }
}

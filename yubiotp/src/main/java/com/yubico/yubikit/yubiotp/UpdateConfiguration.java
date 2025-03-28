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

package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.Version;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class UpdateConfiguration extends KeyboardSlotConfiguration<UpdateConfiguration> {
  private static final Set<Flag> UPDATE_FLAGS;

  static {
    Set<Flag> allowed = new HashSet<>();
    allowed.addAll(
        Arrays.asList(
            EXTFLAG_ALLOW_UPDATE,
            EXTFLAG_DORMANT,
            EXTFLAG_FAST_TRIG,
            EXTFLAG_LED_INV,
            EXTFLAG_SERIAL_API_VISIBLE,
            EXTFLAG_SERIAL_BTN_VISIBLE,
            EXTFLAG_SERIAL_USB_VISIBLE,
            EXTFLAG_USE_NUMERIC_KEYPAD));
    allowed.addAll(
        Arrays.asList(
            TKTFLAG_TAB_FIRST,
            TKTFLAG_APPEND_TAB1,
            TKTFLAG_APPEND_TAB2,
            TKTFLAG_APPEND_DELAY1,
            TKTFLAG_APPEND_DELAY2,
            TKTFLAG_APPEND_CR));
    allowed.addAll(Arrays.asList(CFGFLAG_PACING_10MS, CFGFLAG_PACING_20MS));
    UPDATE_FLAGS = Collections.unmodifiableSet(allowed);
  }

  @Override
  public boolean isSupportedBy(Version version) {
    return YubiOtpSession.FEATURE_UPDATE.isSupportedBy(version) && super.isSupportedBy(version);
  }

  @Override
  protected UpdateConfiguration getThis() {
    return this;
  }

  @Override
  protected UpdateConfiguration updateFlags(Flag flag, boolean value) {
    if (!UPDATE_FLAGS.contains(flag)) {
      throw new IllegalArgumentException("Unsupported TKT flags for update");
    }
    return super.updateFlags(flag, value);
  }

  /**
   * This setting cannot be changed for update, and this method will throw an
   * IllegalArgumentException
   *
   * @param protectSlot2 If true, slot 2 cannot be modified.
   * @return this method will not return normally
   */
  @Override
  public UpdateConfiguration protectSlot2(boolean protectSlot2) {
    throw new IllegalArgumentException("protectSlot2 cannot be applied to UpdateConfiguration");
  }

  /**
   * Inserts tabs in-between different parts of the OTP.
   *
   * @param before inserts a tab before any other output (default: false)
   * @param afterFirst inserts a tab after the static part of the OTP (default: false)
   * @param afterSecond inserts a tab after the end of the OTP (default: false)
   * @return the configuration for chaining
   */
  public UpdateConfiguration tabs(boolean before, boolean afterFirst, boolean afterSecond) {
    updateFlags(TKTFLAG_TAB_FIRST, before);
    updateFlags(TKTFLAG_APPEND_TAB1, afterFirst);
    return updateFlags(TKTFLAG_APPEND_TAB2, afterSecond);
  }

  /**
   * Inserts delays in-between different parts of the OTP.
   *
   * @param afterFirst inserts a delay after the static part of the OTP (default: false)
   * @param afterSecond inserts a delay after the end of the OTP (default: false)
   * @return the configuration for chaining
   */
  public UpdateConfiguration delay(boolean afterFirst, boolean afterSecond) {
    updateFlags(TKTFLAG_APPEND_DELAY1, afterFirst);
    return updateFlags(TKTFLAG_APPEND_DELAY2, afterSecond);
  }
}

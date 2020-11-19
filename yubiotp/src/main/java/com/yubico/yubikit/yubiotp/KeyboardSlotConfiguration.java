/*
 * Copyright (C) 2020 Yubico.
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

abstract class KeyboardSlotConfiguration<T extends KeyboardSlotConfiguration<T>> extends BaseSlotConfiguration<T> {
    protected KeyboardSlotConfiguration() {
        // Unchecked defaults, ignored if not supported
        updateFlags(TKTFLAG_APPEND_CR, true);
        updateFlags(EXTFLAG_FAST_TRIG, true);
    }

    /**
     * Appends a Carriage Return (Enter key press) at the end of the output.
     *
     * @param appendCr if true, the output of the slot will end with a CR (default: true)
     * @return the configuration for chaining
     */
    public T appendCr(boolean appendCr) {
        return updateFlags(TKTFLAG_APPEND_CR, appendCr);
    }

    /**
     * Faster triggering when only slot 1 is configured.
     * This option is always in effect on firmware versions 3.0 and above.
     *
     * @param fastTrigger if true, trigger slot 1 quicker when slot 2 is unconfigured (default: true)
     * @return the configuration for chaining
     */
    public T fastTrigger(boolean fastTrigger) {
        return updateFlags(EXTFLAG_FAST_TRIG, fastTrigger);
    }

    /**
     * Adds a delay between each key press when sending output.
     * This may sometimes be needed if the host system isn't able to handle the default speed at which keystrokes are sent.
     * <p>
     * NOTE: These two flags can be combined to maximize the delay.
     *
     * @param pacing10Ms Adds a ~10ms delay between keystrokes (default: false)
     * @param pacing20Ms Adds a ~20ms delay between keystrokes (default: false)
     * @return the configuration for chaining
     */
    public T pacing(boolean pacing10Ms, boolean pacing20Ms) {
        updateFlags(CFGFLAG_PACING_10MS, pacing10Ms);
        return updateFlags(CFGFLAG_PACING_20MS, pacing20Ms);
    }

    /**
     * Send scancodes for numeric keypad keypresses when sending digits - helps with some keyboard layouts.
     *
     * @param useNumeric true to use the numeric keypad (default: false)
     * @return the configuration for chaining
     */
    public T useNumeric(boolean useNumeric) {
        return updateFlags(EXTFLAG_USE_NUMERIC_KEYPAD, useNumeric);
    }
}

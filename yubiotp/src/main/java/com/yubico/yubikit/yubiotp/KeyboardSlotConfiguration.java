package com.yubico.yubikit.yubiotp;

import com.yubico.yubikit.core.Version;

abstract class KeyboardSlotConfiguration<T extends KeyboardSlotConfiguration<T>> extends BaseSlotConfiguration<T> {
    protected KeyboardSlotConfiguration(Version minVersion) {
        super(minVersion);
        updateTktFlags(TKTFLAG_APPEND_CR, true);
        updateExtFlags(EXTFLAG_FAST_TRIG, true);
    }

    /**
     * Appends a Carriage Return (Enter key press) at the end of the output.
     *
     * @param appendCr if true, the output of the slot will end with a CR (default: true)
     * @return the configuration for chaining
     */
    public T appendCr(boolean appendCr) {
        return updateTktFlags(TKTFLAG_APPEND_CR, appendCr);
    }

    /**
     * Faster triggering when only slot 1 is configured.
     * This option is always in effect on firmware versions 3.0 and above.
     *
     * @param fastTrigger if true, trigger slot 1 quicker when slot 2 is unconfigured (default: true)
     * @return the configuration for chaining
     */
    public T fastTrigger(boolean fastTrigger) {
        return updateExtFlags(EXTFLAG_FAST_TRIG, fastTrigger);
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
        updateTktFlags(CFGFLAG_PACING_10MS, pacing10Ms);
        return updateTktFlags(CFGFLAG_PACING_20MS, pacing20Ms);
    }

    /**
     * Send scancodes for numeric keypad keypresses when sending digits - helps with some keyboard layouts.
     *
     * @param useNumeric true to use the numeric keypad (default: false)
     * @return the configuration for chaining
     */
    public T useNumeric(boolean useNumeric) {
        return updateExtFlags(EXTFLAG_USE_NUMERIC_KEYPAD, useNumeric);
    }
}

package com.yubico.yubikit.piv;

/**
 * Metadata about the PIN or PUK.
 */
public class PinMetadata {
    private final boolean defaultValue;
    private final int totalAttempts;
    private final int attemptsRemaining;

    PinMetadata(boolean defaultValue, int totalAttempts, int attemptsRemaining) {
        this.defaultValue = defaultValue;
        this.totalAttempts = totalAttempts;
        this.attemptsRemaining = attemptsRemaining;
    }

    /**
     * Whether or not the default PIN/PUK is set. The PIN/PUK should be changed from the default to
     * prevent unwanted usage of the application.
     *
     * @return true if the default key is set.
     */
    public boolean isDefaultValue() {
        return defaultValue;
    }

    /**
     * Returns the number of PIN/PUK attempts available after successful verification.
     *
     * @return the total number of attempts allowed
     */
    public int getTotalAttempts() {
        return totalAttempts;
    }

    /**
     * Returns the number of PIN/PUK attempts currently remaining.
     *
     * @return the number of attemts remaining
     */
    public int getAttemptsRemaining() {
        return attemptsRemaining;
    }
}

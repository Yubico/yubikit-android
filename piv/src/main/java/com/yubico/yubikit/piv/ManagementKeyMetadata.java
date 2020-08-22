package com.yubico.yubikit.piv;

/**
 * Metadata about the card management key.
 */
public class ManagementKeyMetadata {
    private final boolean defaultValue;
    private final TouchPolicy touchPolicy;

    ManagementKeyMetadata(boolean defaultValue, TouchPolicy touchPolicy) {
        this.defaultValue = defaultValue;
        this.touchPolicy = touchPolicy;
    }

    /**
     * Whether or not the default card management key is set. The key should be changed from the
     * default to prevent unwanted modification to the application.
     *
     * @return true if the default key is set.
     */
    public boolean isDefaultValue() {
        return defaultValue;
    }

    /**
     * Whether or not the YubiKey sensor needs to be touched when performing authentication.
     * @return the touch policy of the card management key
     */
    public TouchPolicy getTouchPolicy() {
        return touchPolicy;
    }
}

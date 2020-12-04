package com.yubico.yubikit.piv;

/**
 * Supported management key types for use with the PIV YubiKey application.
 */
public enum ManagementKeyType {
    /**
     * 3-DES (the default).
     */
    TDES((byte) 0x03, "DESede", 24, 8),
    /**
     * AES-128.
     */
    AES128((byte) 0x08, "AES", 16, 16),
    /**
     * AES-191.
     */
    AES192((byte) 0x0a, "AES", 24, 16),
    /**
     * AES-256.
     */
    AES256((byte) 0x0c, "AES", 32, 16);

    public final byte value;
    public final String cipherName;
    public final int keyLength;
    public final int challengeLength;

    ManagementKeyType(byte value, String cipherName, int keyLength, int challengeLength) {
        this.value = value;
        this.cipherName = cipherName;
        this.keyLength = keyLength;
        this.challengeLength = challengeLength;
    }

    public static ManagementKeyType fromValue(byte value) {
        for (ManagementKeyType type : ManagementKeyType.values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Not a valid ManagementKeyType:" + value);
    }
}

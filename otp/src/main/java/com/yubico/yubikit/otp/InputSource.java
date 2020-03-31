package com.yubico.yubikit.otp;

/**
 * Currently provided keyboard layouts/input sources within SDK for OTP parser
 */
public enum InputSource {
    US(0),
    DE(1),
    DECH(2);

    public final int value;

    InputSource(int value) {
        this.value = value;
    }

    public static InputSource fromValue(int value) {
        for (InputSource type : InputSource.values()) {
            if (type.value == value) {
                return type;
            }
        }
        throw new IllegalArgumentException("Not a valid InputSource :" + value);
    }
}

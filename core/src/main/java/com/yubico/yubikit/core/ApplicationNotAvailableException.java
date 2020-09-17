package com.yubico.yubikit.core;

/**
 * The application is either disabled or not supported on the connected YubiKey.
 */
public class ApplicationNotAvailableException extends CommandException {
    public ApplicationNotAvailableException(String message) {
        super(message);
    }

    public ApplicationNotAvailableException(String message, Throwable cause) {
        super(message, cause);
    }
}

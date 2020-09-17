package com.yubico.yubikit.core;

/**
 * An error response from a YubiKey.
 */
public class CommandException extends Exception {
    public CommandException(String message) {
        super(message);
    }

    public CommandException(String message, Throwable cause) {
        super(message, cause);
    }
}

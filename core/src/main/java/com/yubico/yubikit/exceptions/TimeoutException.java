package com.yubico.yubikit.exceptions;

/**
 * The operation timed out waiting for something.
 */
public class TimeoutException extends CommandException {
    public TimeoutException(String message) {
        super(message);
    }

    public TimeoutException(String message, Throwable cause) {
        super(message, cause);
    }
}

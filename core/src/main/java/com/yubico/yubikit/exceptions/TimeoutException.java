package com.yubico.yubikit.exceptions;

import java.io.IOException;

/**
 * The operation timed out waiting for something.
 */
public class TimeoutException extends IOException {
    public TimeoutException(String message) {
        super(message);
    }

    public TimeoutException(String message, Throwable cause) {
        super(message, cause);
    }
}

package com.yubico.yubikit.core.otp;

import com.yubico.yubikit.core.CommandException;

/**
 * The command was rejected by the YubiKey.
 */
public class CommandRejectedException extends CommandException {
    public CommandRejectedException(String message) {
        super(message);
    }
}

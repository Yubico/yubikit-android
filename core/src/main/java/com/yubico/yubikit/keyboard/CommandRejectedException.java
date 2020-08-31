package com.yubico.yubikit.keyboard;

import com.yubico.yubikit.exceptions.CommandException;

/**
 * The command was rejected by the YubiKey.
 */
public class CommandRejectedException extends CommandException {
    public CommandRejectedException(String message) {
        super(message);
    }
}

package com.yubico.yubikit.configurator;

import com.yubico.yubikit.exceptions.BadRequestException;

public class UnexpectedSymbolException extends BadRequestException {
    static final long serialVersionUID = 1L;
    public UnexpectedSymbolException(String message) {
        super(message);
    }
}

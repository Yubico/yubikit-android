package com.yubico.yubikit.configurator;

public class UnexpectedSymbolException extends Exception {
    static final long serialVersionUID = 1L;
    public UnexpectedSymbolException(String message) {
        super(message);
    }
}

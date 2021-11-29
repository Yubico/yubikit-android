package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.TouchPolicy;

import java.security.KeyStore;

public class PivKeyStoreKeyParameters implements KeyStore.ProtectionParameter {
    final PinPolicy pinPolicy;
    final TouchPolicy touchPolicy;

    public PivKeyStoreKeyParameters(PinPolicy pinPolicy, TouchPolicy touchPolicy) {
        this.pinPolicy = pinPolicy;
        this.touchPolicy = touchPolicy;
    }
}

package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.piv.PivSession;

import java.security.KeyStore;

public class PivLoadStoreParameter implements KeyStore.LoadStoreParameter {
    final PivSession piv;

    public PivLoadStoreParameter(PivSession piv) {
        this.piv = piv;
    }

    @Override
    public KeyStore.ProtectionParameter getProtectionParameter() {
        return null;
    }
}

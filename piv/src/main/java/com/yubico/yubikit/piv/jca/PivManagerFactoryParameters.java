package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.piv.PivSession;

import javax.annotation.Nullable;
import javax.net.ssl.ManagerFactoryParameters;

public class PivManagerFactoryParameters implements ManagerFactoryParameters {
    final PivSession piv;
    @Nullable
    final char[] pin;

    public PivManagerFactoryParameters(PivSession piv, @Nullable char[] pin) {
        this.piv = piv;
        this.pin = pin;
    }
}

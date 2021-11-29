package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.Nullable;

public class PivAlgorithmParameterSpec implements AlgorithmParameterSpec {
    final PivSession piv;
    final Slot slot;
    final PinPolicy pinPolicy;
    final TouchPolicy touchPolicy;
    @Nullable final Pin pin;

    public PivAlgorithmParameterSpec(PivSession piv, Slot slot, @Nullable PinPolicy pinPolicy, @Nullable TouchPolicy touchPolicy, @Nullable Pin pin) {
        this.piv = piv;
        this.slot = slot;
        this.pinPolicy = pinPolicy != null ? pinPolicy : PinPolicy.DEFAULT;
        this.touchPolicy = touchPolicy != null ? touchPolicy : TouchPolicy.DEFAULT;
        this.pin = pin;
    }
}

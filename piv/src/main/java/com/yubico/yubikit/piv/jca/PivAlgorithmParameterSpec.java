package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;

import java.security.spec.AlgorithmParameterSpec;

import javax.annotation.Nullable;

public class PivAlgorithmParameterSpec implements AlgorithmParameterSpec {
    final PivSessionProvider sessionProvider;
    final Slot slot;
    final PinPolicy pinPolicy;
    final TouchPolicy touchPolicy;

    public PivAlgorithmParameterSpec(PivSessionProvider sessionProvider, Slot slot, @Nullable PinPolicy pinPolicy, @Nullable TouchPolicy touchPolicy) {
        this.sessionProvider = sessionProvider;
        this.slot = slot;
        this.pinPolicy = pinPolicy != null ? pinPolicy : PinPolicy.DEFAULT;
        this.touchPolicy = touchPolicy != null ? touchPolicy : TouchPolicy.DEFAULT;
    }
}

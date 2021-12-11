package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.annotation.Nullable;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

public class PivAlgorithmParameterSpec implements AlgorithmParameterSpec, Destroyable {
    final Slot slot;
    final PinPolicy pinPolicy;
    final TouchPolicy touchPolicy;
    @Nullable
    final char[] pin;
    private boolean destroyed = false;

    public PivAlgorithmParameterSpec(Slot slot, @Nullable PinPolicy pinPolicy, @Nullable TouchPolicy touchPolicy, @Nullable char[] pin) {
        this.slot = slot;
        this.pinPolicy = pinPolicy != null ? pinPolicy : PinPolicy.DEFAULT;
        this.touchPolicy = touchPolicy != null ? touchPolicy : TouchPolicy.DEFAULT;
        this.pin = pin != null ? Arrays.copyOf(pin, pin.length) : null;
    }

    @Override
    public void destroy() {
        if (pin != null) {
            Arrays.fill(pin, (char) 0);
        }
        destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}

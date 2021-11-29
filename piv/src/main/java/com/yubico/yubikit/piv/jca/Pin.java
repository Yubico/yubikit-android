package com.yubico.yubikit.piv.jca;

import java.util.Arrays;

import javax.security.auth.Destroyable;

/**
 * Wrapper-class for holding a PIN. Call {@link #destroy} when the PIN is no longer needed.
 */
public class Pin implements Destroyable {
    final char[] buffer;
    private boolean destroyed = false;

    /**
     * Constructs a new Pin from a char[].
     *
     * The array will be copied, and once constructed, the original no longer needed.
     *
     * @param pin
     */
    public Pin(char[] pin) {
        this.buffer = Arrays.copyOf(pin, pin.length);
    }

    public Pin(String pin) {
        this.buffer = pin.toCharArray();
    }

    @Override
    public void destroy() {
        Arrays.fill(buffer, (char) 0);
        destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}

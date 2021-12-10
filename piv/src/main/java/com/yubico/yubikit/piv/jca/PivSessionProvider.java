package com.yubico.yubikit.piv.jca;

import com.yubico.yubikit.core.Logger;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.piv.InvalidPinException;
import com.yubico.yubikit.piv.PivSession;

import java.io.IOException;
import java.util.Arrays;
import java.util.function.Function;

import javax.annotation.Nullable;
import javax.security.auth.Destroyable;

public interface PivSessionProvider {
    @Nullable
    <T> T use(Function<PivSession, T> function);

    class FromInstance implements PivSessionProvider {
        private final PivSession piv;

        public FromInstance(PivSession piv) {
            this.piv = piv;
        }

        @Nullable
        @Override
        public <T> T use(Function<PivSession, T> function) {
            return function.apply(piv);
        }
    }

    class FromInstanceWithPin implements PivSessionProvider, Destroyable {
        private final PivSession piv;
        private final char[] pin;
        private boolean destroyed = false;

        public FromInstanceWithPin(PivSession piv, char[] pin) {
            this.piv = piv;
            this.pin = Arrays.copyOf(pin, pin.length);
        }

        @Nullable
        @Override
        public <T> T use(Function<PivSession, T> function) {
            try {
                piv.verifyPin(pin);
            } catch (IOException | ApduException | InvalidPinException e) {
                Logger.e("Failed to validate PIN", e);
                return null;
            }
            return function.apply(piv);
        }

        @Override
        public void destroy() {
            Arrays.fill(pin, (char) 0);
            destroyed = true;
        }

        @Override
        public boolean isDestroyed() {
            return destroyed;
        }
    }
}

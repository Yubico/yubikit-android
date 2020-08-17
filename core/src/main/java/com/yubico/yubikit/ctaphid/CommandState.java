package com.yubico.yubikit.ctaphid;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Provides control over an ongoing CTAP2 operation.
 * <p>
 * Override onKeepAliveMessage to react to keepalive messages send periodically from the YubiKey.
 * Call {@link #cancel()} to cancel an ongoing operation.
 */
public class CommandState {
    private final AtomicBoolean cancelled = new AtomicBoolean();

    /**
     * Override this method to handle keep-alive messages sent from the YubiKey.
     *
     * @param status The keep alive status byte
     */
    public void onKeepAliveStatus(byte status) {
    }

    /**
     * Cancel an ongoing CTAP2 command, by sending a CTAP cancel command. This will cause the
     * YubiKey to return a CtapError with the error code 0x2d (ERR_KEEPALIVE_CANCEL).
     */
    public final void cancel() {
        cancelled.set(true);
    }

    final boolean isCancelled() {
        return cancelled.get();
    }
}

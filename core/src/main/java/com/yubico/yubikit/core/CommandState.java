package com.yubico.yubikit.core;

/**
 * Provides control over an ongoing YubiKey operation.
 * <p>
 * Override onKeepAliveMessage to react to keepalive messages send periodically from the YubiKey.
 * Call {@link #cancel()} to cancel an ongoing operation.
 */
public class CommandState {
    public static final byte STATUS_PROCESSING = 1;
    public static final byte STATUS_UPNEEDED = 2;

    private boolean cancelled = false;

    /**
     * Override this method to handle keep-alive messages sent from the YubiKey.
     * The default implementation will log the event.
     *
     * @param status The keep alive status byte
     */
    public void onKeepAliveStatus(byte status) {
        Logger.d(String.format("received keepalive status: %x", status));
    }

    /**
     * Cancel an ongoing CTAP2 command, by sending a CTAP cancel command. This will cause the
     * YubiKey to return a CtapError with the error code 0x2d (ERR_KEEPALIVE_CANCEL).
     */
    public final synchronized void cancel() {
        cancelled = true;
    }

    /* Internal use only */
    public final synchronized boolean waitForCancel(long ms) {
        if (!cancelled && ms > 0) {
            try {
                wait(ms);
            } catch (InterruptedException e) {
                Logger.d("Thread interrupted, cancelling command");
                cancelled = true;
                Thread.currentThread().interrupt();
            }
        }
        return cancelled;
    }
}

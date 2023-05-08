/*
 * Copyright (C) 2020-2022 Yubico.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yubico.yubikit.core.application;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides control over an ongoing YubiKey operation.
 * <p>
 * Override onKeepAliveMessage to react to keepalive messages send periodically from the YubiKey.
 * Call {@link #cancel()} to cancel an ongoing operation.
 */
public class CommandState {

    private static final Logger logger = LoggerFactory.getLogger(CommandState.class);

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
        logger.debug("received keepalive status: {}", status);
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
                logger.debug("Thread interrupted, cancelling command");
                cancelled = true;
                Thread.currentThread().interrupt();
            }
        }
        return cancelled;
    }
}

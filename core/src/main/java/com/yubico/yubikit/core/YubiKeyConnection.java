package com.yubico.yubikit.core;

import java.io.Closeable;

/**
 * A connection to a YubiKey, which typically exposes a way to send and receive data.
 */
public interface YubiKeyConnection extends Closeable {
}

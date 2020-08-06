package com.yubico.yubikit;

import java.io.Closeable;
import java.io.IOException;

import javax.annotation.Nullable;

public interface OtpConnection extends Closeable {
    /**
     * Synchronously sends a command to the YubiKey, and reads a response.
     * @param slot The slot to target for the command.
     * @param payload The binary data to send, which must not exceed 64 bytes.
     * @param expectedResponseLength The expected length of the response, 0 for no response.
     * @return The response back from the YubiKey
     * @throws IOException in case of communication error
     */
    byte[] transceive(byte slot, @Nullable byte[] payload, int expectedResponseLength) throws IOException;

    /**
     * Reads the status data from the YubiKey.
     * @return The binary status data from the YubiKey.
     * @throws IOException in case of communication error
     */
    byte[] readStatus() throws IOException;
}

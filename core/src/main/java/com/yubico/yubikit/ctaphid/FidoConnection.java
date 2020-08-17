package com.yubico.yubikit.ctaphid;

import java.io.Closeable;
import java.io.IOException;

public interface FidoConnection extends Closeable {
    void sendPacket(byte[] packet) throws IOException;
    int readPacket(byte[] packet) throws IOException;
}

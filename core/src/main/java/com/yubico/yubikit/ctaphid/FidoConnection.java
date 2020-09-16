package com.yubico.yubikit.ctaphid;

import java.io.Closeable;
import java.io.IOException;

public interface FidoConnection extends Closeable {
    int PACKET_SIZE = 64;

    void send(byte[] packet) throws IOException;
    void receive(byte[] packet) throws IOException;
}

package com.yubico.yubikit.core.fido;

import com.yubico.yubikit.core.YubiKeyConnection;

import java.io.IOException;

public interface FidoConnection extends YubiKeyConnection {
    int PACKET_SIZE = 64;

    void send(byte[] packet) throws IOException;
    void receive(byte[] packet) throws IOException;
}

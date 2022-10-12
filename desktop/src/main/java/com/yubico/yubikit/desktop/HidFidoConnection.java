/*
 * Copyright (C) 2020 Yubico AB - All Rights Reserved
 * Unauthorized copying and/or distribution of this file, via any medium is strictly prohibited
 * Proprietary and confidential
 */
package com.yubico.yubikit.desktop;

import com.yubico.yubikit.core.fido.FidoConnection;

import org.hid4java.HidDevice;

import java.io.IOException;

public class HidFidoConnection implements FidoConnection {
    private static final int TIMEOUT = 1000;

    private final HidDevice hidDevice;

    public HidFidoConnection(HidDevice hidDevice) throws IOException {
        if (hidDevice.isOpen()) {
            throw new IOException("Device already open");
        }
        hidDevice.open();
        this.hidDevice = hidDevice;
    }

    @Override
    public void close() {
        hidDevice.close();
    }

    @Override
    public void send(byte[] packet) throws IOException {
        int sent = hidDevice.write(packet, packet.length, (byte) 0);
        if (sent < 0) {
            throw new IOException(hidDevice.getLastErrorMessage());
        } else if (sent != PACKET_SIZE) {
            throw new IOException("Unexpected amount of data sent: " + sent);
        }
    }

    @Override
    public void receive(byte[] packet) throws IOException {
        int received = hidDevice.read(packet, TIMEOUT);
        if (received < 0) {
            throw new IOException(hidDevice.getLastErrorMessage());
        } else if (received != PACKET_SIZE) {
            throw new IOException("Unexpected amount of data read: " + received);
        }
    }
}

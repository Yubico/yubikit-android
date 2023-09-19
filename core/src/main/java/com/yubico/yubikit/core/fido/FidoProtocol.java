/*
 * Copyright (C) 2020-2023 Yubico.
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
package com.yubico.yubikit.core.fido;

import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.util.StringUtils;

import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.annotation.Nullable;

public class FidoProtocol implements Closeable {

    public static final byte TYPE_INIT = (byte) 0x80;

    public static final byte CTAPHID_PING = TYPE_INIT | 0x01;
    public static final byte CTAPHID_MSG = TYPE_INIT | 0x03;
    public static final byte CTAPHID_LOCK = TYPE_INIT | 0x04;
    public static final byte CTAPHID_INIT = TYPE_INIT | 0x06;
    public static final byte CTAPHID_WINK = TYPE_INIT | 0x08;
    public static final byte CTAPHID_CBOR = TYPE_INIT | 0x10;
    public static final byte CTAPHID_CANCEL = TYPE_INIT | 0x11;

    public static final byte CTAPHID_ERROR = TYPE_INIT | 0x3f;
    public static final byte CTAPHID_KEEPALIVE = TYPE_INIT | 0x3b;

    private final CommandState defaultState = new CommandState();

    private final FidoConnection connection;

    private final Version version;
    private int channelId;

    private static final org.slf4j.Logger logger = LoggerFactory.getLogger(FidoProtocol.class);

    public FidoProtocol(FidoConnection connection) throws IOException {
        this.connection = connection;

        // init
        byte[] nonce = new byte[8];
        new SecureRandom().nextBytes(nonce);

        channelId = 0xffffffff;
        ByteBuffer buffer = ByteBuffer.wrap(sendAndReceive(CTAPHID_INIT, nonce, null));
        byte[] responseNonce = new byte[nonce.length];
        buffer.get(responseNonce);
        if (!MessageDigest.isEqual(nonce, responseNonce)) {
            throw new IOException("Got wrong nonce!");
        }

        channelId = buffer.getInt();
        buffer.get(); // U2F HID version
        byte[] versionBytes = new byte[3];
        buffer.get(versionBytes);
        version = Version.fromBytes(versionBytes);
        buffer.get(); // Capabilities
        Logger.debug(logger, "FIDO connection set up with channel ID: {}", String.format("0x%08x", channelId));
    }

    public byte[] sendAndReceive(byte cmd, byte[] payload, @Nullable CommandState state) throws IOException {
        state = state != null ? state : defaultState;

        ByteBuffer toSend = ByteBuffer.wrap(payload);
        byte[] buffer = new byte[FidoConnection.PACKET_SIZE];
        ByteBuffer packet = ByteBuffer.wrap(buffer);
        byte seq = 0;

        // Send request
        packet.putInt(channelId).put(cmd).putShort((short) toSend.remaining());
        do {
            toSend.get(buffer, packet.position(), Math.min(toSend.remaining(), packet.remaining()));
            connection.send(buffer);
            Logger.trace(logger, "{} bytes sent over fido: {}", buffer.length, StringUtils.bytesToHex(buffer));
            Arrays.fill(buffer, (byte) 0);
            packet.clear();
            packet.putInt(channelId).put((byte) (0x7f & seq++));
        } while (toSend.hasRemaining());

        // Read response
        seq = 0;
        ByteBuffer response = null;
        do {
            packet.clear();
            if (state.waitForCancel(0)) {
                Logger.debug(logger, "sending CTAP cancel...");
                Arrays.fill(buffer, (byte) 0);
                packet.putInt(channelId).put(CTAPHID_CANCEL);
                connection.send(buffer);
                Logger.trace(logger, "Sent over fido: {}", StringUtils.bytesToHex(buffer));
                packet.clear();
            }

            connection.receive(buffer);
            Logger.trace(logger, "Received over fido: {}", StringUtils.bytesToHex(buffer));
            int responseChannel = packet.getInt();
            if (responseChannel != channelId) {
                throw new IOException(String.format("Wrong Channel ID. Expecting: %d, Got: %d", channelId, responseChannel));
            }
            if (response == null) {
                byte responseCmd = packet.get();
                if (responseCmd == cmd) {
                    response = ByteBuffer.allocate(packet.getShort());
                } else if (responseCmd == CTAPHID_KEEPALIVE) {
                    state.onKeepAliveStatus(packet.get());
                    continue;
                } else if (responseCmd == CTAPHID_ERROR) {
                    throw new IOException(String.format("CTAPHID error: %02x", packet.get()));
                } else {
                    throw new IOException(String.format("Wrong response command. Expecting: %x, Got: %x", cmd, responseCmd));
                }
            } else {
                byte responseSeq = packet.get();
                if (responseSeq != seq++) {
                    throw new IOException(String.format("Wrong sequence number. Expecting %d, Got: %d", seq - 1, responseSeq));
                }
            }
            response.put(buffer, packet.position(), Math.min(packet.remaining(), response.remaining()));
        } while (response == null || response.hasRemaining());

        return response.array();
    }

    public Version getVersion() {
        return version;
    }

    @Override
    public void close() throws IOException {
        connection.close();
        Logger.debug(logger, "fido connection closed");
    }
}
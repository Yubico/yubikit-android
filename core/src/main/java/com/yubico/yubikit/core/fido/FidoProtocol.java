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
package com.yubico.yubikit.core.fido;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.util.StringUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.annotation.Nullable;

public class FidoProtocol implements Closeable {

    private static final Logger logger = LoggerFactory.getLogger(FidoProtocol.class);

    public static final byte TYPE_INIT = (byte) 0x80;

    private static final byte CMD_PING = TYPE_INIT | 0x01;
    private static final byte CMD_APDU = TYPE_INIT | 0x03;
    private static final byte CMD_INIT = TYPE_INIT | 0x06;
    private static final byte CMD_WINK = TYPE_INIT | 0x08;
    private static final byte CMD_CANCEL = TYPE_INIT | 0x11;

    private static final byte STATUS_ERROR = TYPE_INIT | 0x3f;
    private static final byte STATUS_KEEPALIVE = TYPE_INIT | 0x3b;

    private final CommandState defaultState = new CommandState();

    private final FidoConnection connection;

    private final Version version;
    private int channelId;

    public FidoProtocol(FidoConnection connection) throws IOException {
        this.connection = connection;

        // init
        byte[] nonce = new byte[8];
        new SecureRandom().nextBytes(nonce);

        channelId = 0xffffffff;
        ByteBuffer buffer = ByteBuffer.wrap(sendAndReceive(CMD_INIT, nonce, null));
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
        logger.debug("FIDO connection set up with channel ID: {}", String.format("0x%08x", channelId));
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
            logger.debug("{} bytes sent over fido: {}", buffer.length, StringUtils.bytesToHex(buffer));
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
                logger.debug("sending CTAP cancel...");
                Arrays.fill(buffer, (byte) 0);
                packet.putInt(channelId).put(CMD_CANCEL);
                connection.send(buffer);
                logger.trace("Sent over fido: {}", StringUtils.bytesToHex(buffer));
                packet.clear();
            }

            connection.receive(buffer);
            logger.trace("Received over fido: {}", StringUtils.bytesToHex(buffer));
            int responseChannel = packet.getInt();
            if (responseChannel != channelId) {
                throw new IOException(String.format("Wrong Channel ID. Expecting: %d, Got: %d", channelId, responseChannel));
            }
            if (response == null) {
                byte responseCmd = packet.get();
                if (responseCmd == cmd) {
                    response = ByteBuffer.allocate(packet.getShort());
                } else if (responseCmd == STATUS_KEEPALIVE) {
                    state.onKeepAliveStatus(packet.get());
                    continue;
                } else if (responseCmd == STATUS_ERROR) {
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
        logger.debug("fido connection closed");
    }
}
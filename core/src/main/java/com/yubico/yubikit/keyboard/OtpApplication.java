package com.yubico.yubikit.keyboard;

import com.yubico.yubikit.exceptions.TimeoutException;
import com.yubico.yubikit.utils.CommandState;
import com.yubico.yubikit.utils.Logger;
import com.yubico.yubikit.utils.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import javax.annotation.Nullable;

public class OtpApplication implements Closeable {
    private static final int FEATURE_RPT_SIZE = 8;
    private static final int FEATURE_RPT_DATA_SIZE = FEATURE_RPT_SIZE - 1;

    private static final int SLOT_DATA_SIZE = 64;
    private static final int FRAME_SIZE = SLOT_DATA_SIZE + 6;

    private static final int RESP_PENDING_FLAG = 0x40;    /* Response pending flag */
    private static final int SLOT_WRITE_FLAG = 0x80;    /* Write flag - set by app - cleared by device */
    private static final int RESP_TIMEOUT_WAIT_FLAG = 0x20;    /* Waiting for timeout operation - seconds left in lower 5 bits */
    private static final int DUMMY_REPORT_WRITE = 0x8f;    /* Write a dummy report to force update or abort */

    private static final int SEQUENCE_MASK = 0x1f;
    private static final int SEQUENCE_OFFSET = 0x4;

    private final CommandState defaultState = new CommandState();

    private final OtpConnection connection;

    public OtpApplication(OtpConnection connection) {
        this.connection = connection;
    }

    @Override
    public void close() throws IOException {
        connection.close();
    }

    /**
     * Sends a command to the YubiKey, and reads the response.
     * If the command results in a configuration update, the programming sequence number is verified
     * and the updated status bytes are returned.
     *
     * @param slot  the slot to send to
     * @param data  the data payload to send
     * @param state optional CommandState for listening for user presence requirement and for cancelling a command
     * @return response data (including CRC) in the case of data, or an updated status struct
     * @throws IOException in case of communication error
     */
    public byte[] transceive(byte slot, @Nullable byte[] data, @Nullable CommandState state) throws IOException {
        byte[] payload;
        if (data == null) {
            payload = new byte[SLOT_DATA_SIZE];
        } else if (data.length > SLOT_DATA_SIZE) {
            throw new IllegalArgumentException("Payload too large for HID frame!");
        } else {
            payload = Arrays.copyOf(data, SLOT_DATA_SIZE);
        }
        return readFrame(sendFrame(slot, payload), state != null ? state : defaultState);
    }

    /**
     * Receive status bytes from YubiKey
     *
     * @return status bytes (first 3 bytes are the firmware version)
     * @throws IOException in case of communication error
     */
    public byte[] readStatus() throws IOException {
        byte[] featureReport = readFeatureReport();
        // disregard the first and last byte in the feature report
        return Arrays.copyOfRange(featureReport, 1, featureReport.length - 1);
    }

    /* Read a single 8 byte feature report */
    private byte[] readFeatureReport() throws IOException {
        byte[] bufferRead = new byte[FEATURE_RPT_SIZE];
        int bytesRead = connection.readFeatureReport(bufferRead);
        if (bytesRead < 0) {
            throw new IOException("Can't read the data");
        }
        if (bytesRead < FEATURE_RPT_SIZE) {
            throw new IOException("Size of blob is smaller than expected");
        }
        Logger.d("READ FEATURE REPORT: " + StringUtils.bytesToHex(bufferRead));
        return bufferRead;
    }

    /* Write a single 8 byte feature report */
    private void writeFeatureReport(byte[] buffer) throws IOException {
        Logger.d("WRITE FEATURE REPORT: " + StringUtils.bytesToHex(buffer));
        int bytesSentPackage = connection.writeFeatureReport(buffer);
        if (bytesSentPackage < 0) {
            throw new IOException("Can't write the data");
        }
        if (bytesSentPackage < FEATURE_RPT_SIZE) {
            throw new IOException("Some of the data was not sent");
        }
    }

    /* Sleep for up to ~1s waiting for the WRITE flag to be unset */
    private void awaitReadyToWrite() throws IOException {
        for (int i = 0; i < 20; i++) {
            if ((readFeatureReport()[FEATURE_RPT_DATA_SIZE] & SLOT_WRITE_FLAG) == 0) {
                return;
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                //Ignore
            }
        }
        throw new IOException("Timeout waiting for YubiKey to become ready to receive");
    }

    /* All-zero packets are skipped, except for the very first and last packets */
    private static boolean shouldSend(byte[] packet, byte seq) {
        if (seq == 0 || seq == 9) {
            return true;
        }
        for (int i = 0; i < 7; i++) {
            if (packet[i] != 0) {
                return true;
            }
        }
        return false;
    }

    /* Packs and sends one 70 byte frame */
    private int sendFrame(byte slot, byte[] payload) throws IOException {
        Logger.d(String.format("Sending payload over HID to slot 0x%02x: ", 0xff & slot) + StringUtils.bytesToHex(payload));

        // Format Frame
        ByteBuffer buf = ByteBuffer.allocate(FRAME_SIZE)
                .order(ByteOrder.LITTLE_ENDIAN)
                .put(payload)
                .put(slot)
                .putShort(ChecksumUtils.calculateCrc(payload, payload.length))
                .put(new byte[3]);  // 3-byte filler
        buf.flip();

        // Send frame
        int programmingSequence = readFeatureReport()[SEQUENCE_OFFSET];
        byte seq = 0;
        byte[] report = new byte[FEATURE_RPT_SIZE];
        while (buf.hasRemaining()) {
            buf.get(report, 0, FEATURE_RPT_DATA_SIZE);
            if (shouldSend(report, seq)) {
                report[FEATURE_RPT_DATA_SIZE] = (byte) (0x80 | seq);
                awaitReadyToWrite();
                writeFeatureReport(report);
            }
            seq++;
        }
        return programmingSequence;
    }

    /* Reads one frame */
    private byte[] readFrame(int programmingSequence, CommandState state) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        byte seq = 0;
        boolean needsTouch = false;

        while (true) {
            byte[] report = readFeatureReport();
            byte statusByte = report[FEATURE_RPT_DATA_SIZE];
            if ((statusByte & RESP_PENDING_FLAG) != 0) { // Response packet
                if (seq == (statusByte & SEQUENCE_MASK)) {
                    // Correct sequence
                    stream.write(report, 0, FEATURE_RPT_DATA_SIZE);
                    seq++;
                } else if (0 == (statusByte & SEQUENCE_MASK)) {
                    // Transmission complete
                    resetState();
                    byte[] response = stream.toByteArray();
                    Logger.d(response.length + " bytes read over HID: " + StringUtils.bytesToHex(response));
                    return response;
                }
            } else if (statusByte == 0) { // Status response
                if (stream.size() > 0) {
                    throw new IOException("Incomplete transfer");
                } else if (report[SEQUENCE_OFFSET] == programmingSequence + 1) {
                    // Sequence updated, return status.
                    byte[] status = Arrays.copyOfRange(report, 1, 7); // Skip first and last bytes
                    Logger.d("HID programming sequence updated. New status: " + StringUtils.bytesToHex(status));
                    return status;
                } else if (needsTouch) {
                    throw new TimeoutException("Timed out waiting for touch");
                } else {
                    throw new IOException("No data");
                }
            } else { // Need to wait
                long timeout;
                if ((statusByte & RESP_TIMEOUT_WAIT_FLAG) != 0) {
                    state.onKeepAliveStatus(CommandState.STATUS_UPNEEDED);
                    needsTouch = true;
                    timeout = 100;
                } else {
                    state.onKeepAliveStatus(CommandState.STATUS_PROCESSING);
                    timeout = 20;
                }
                if (state.waitForCancel(timeout)) {
                    resetState();
                    throw new TimeoutException("Command cancelled by CommandState");
                }
            }
        }
    }

    /**
     * Reset the state of YubiKey from reading/means that there won't be any data returned
     */
    private void resetState() throws IOException {
        byte[] buffer = new byte[FEATURE_RPT_SIZE];
        buffer[FEATURE_RPT_SIZE - 1] = (byte) DUMMY_REPORT_WRITE; /* Invalid sequence = update only */
        writeFeatureReport(buffer);
    }
}
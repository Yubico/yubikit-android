/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.transport.usb;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbInterface;

import com.yubico.yubikit.utils.ChecksumUtils;
import com.yubico.yubikit.utils.Logger;
import com.yubico.yubikit.utils.StringUtils;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

/**
 * Class that provides interface to read and send data over YubiKey HID (keyboard) interface
 */
public class UsbHidConnection implements Closeable {

    /**
     * Timeout for control transfer
     */
    private static final int TIMEOUT = 1000;

    /**
     * Timeout to wait for flag write to be cleared for next blob
     * Yubikey low-level interface section 2.4 (Report arbitration polling) specifies
     * a 600 ms timeout for a Yubikey to process something written to it.
     * Where can that document be found?
     * It has been discovered that for swap 600 is not enough, swapping can worst
     * case take 920 ms, which we then add 25% to for safety margin, arriving at
     * 1150 ms.
     */
    private static final int WAIT_FOR_WRITE_FLAG_TIMEOUT = 1150;

    private final UsbDeviceConnection connection;
    private final UsbInterface hidInterface;

    private static final int TYPE_CLASS = 0x20;
    private static final int RECEIPIENT_INTERFACE = 0x01;
    private static final int HID_GET_REPORT = 0x01;
    private static final int HID_SET_REPORT = 0x09;
    private static final int REPORT_TYPE_FEATURE = 0x03;
    private static final int FEATURE_RPT_SIZE = 8;
    private static final int FEATURE_RPT_DATA_SIZE = FEATURE_RPT_SIZE - 1;

    private static final int SLOT_DATA_SIZE = 64;

    private static final int RESP_PENDING_FLAG= 0x40;	/* Response pending flag */
    private static final int SLOT_WRITE_FLAG = 0x80;	/* Write flag - set by app - cleared by device */
    private static final int RESP_TIMEOUT_WAIT_FLAG	= 0x20;	/* Waiting for timeout operation - seconds left in lower 5 bits */
    private static final int DUMMY_REPORT_WRITE	= 0x8f;	/* Write a dummy report to force update or abort */

    /**
     * Sets endpoints and connection
     * Note: this method is protected to allow dependency injection for UT
     * @param connection open usb connection
     * @param hidInterface HID interface that was claimed
     * NOTE: controlTransfer works only with endpoint zero.
     */
    UsbHidConnection(UsbDeviceConnection connection, UsbInterface hidInterface){
        this.connection = connection;
        this.hidInterface = hidInterface;
        Logger.d("usb connection opened");
    }

    @Override
    public void close() {
        // NODE: when we release HID interface YubiKey will be recognized as keyboard again,
        // it may give you a flash of UI on Android (notification how to handle Keyboard)
        // which means your active Activity may got to background for a moment
        // be aware of that and make sure that UI can handle that
        connection.releaseInterface(hidInterface);
        connection.close();
        Logger.d("usb connection closed");
    }

    /**
     * Receive status bytes from YubiKey
     * @return status bytes (first 3 bytes are the firmware version)
     * @throws IOException
     */
    public byte[] getStatus() throws IOException {
        byte[] featureReport = readFeatureReport();
        // disregards the first byte in each feature report
        byte[] status = Arrays.copyOfRange(featureReport, 1, featureReport.length);
        Logger.d("status received over hid: " + StringUtils.bytesToHex(status));
        return status;
    }

    /**
     * Send data to YubiKey
     * @param slot slot that command targets (or command that is going to be sent)
     * @param buffer data that needs to be sent
     * @return number of bytes that has been sent
     * @throws IOException
     */
    public int send(byte slot, byte[] buffer) throws IOException {
        if (buffer == null) {
            buffer = new byte[0];
        }
        if (buffer.length > SLOT_DATA_SIZE) {
            throw new IOException("Size of buffer is bigger than 64");
        }

        Frame frame = new Frame();

        /* Insert data and set slot # */
        System.arraycopy(buffer, 0, frame.payload, 0, buffer.length);
        frame.slot = slot;

        /* Append slot checksum */
        frame.crc = ChecksumUtils.calculateCrc(frame.payload, frame.payload.length);

	    // Chop up the data into parts that fits into the payload of a feature report.
	    // Set the sequence number | 0x80 in the end of the feature report.
	    // When the Yubikey has processed it,  it will clear this byte, signaling that the next part can be sent */

        int bytesSent = 0;
        int sequence = 0;
        int offset = 0;

        // buffer is always 70 bytes, sent by 7 byte blobs + 1 byte flags/sequence
        byte[] bufferToSend = frame.toByteArray();
        Logger.d(bufferToSend.length + " bytes sent over hid: " + StringUtils.bytesToHex(bufferToSend));
        int numPackages = bufferToSend.length / FEATURE_RPT_DATA_SIZE;
        boolean packageSent = false;
	    do {
	        if (!packageSent || isReadyToWrite()) {
                byte[] packageToSend = Arrays.copyOfRange(bufferToSend, offset, offset + FEATURE_RPT_DATA_SIZE);
                offset += FEATURE_RPT_DATA_SIZE;
                /* Ignore parts that are all zeroes except first and last to speed up the transfer */
                packageSent = sequence == 0 || sequence == numPackages - 1 || !allZeros(packageToSend);
                if (packageSent) {
                    ByteArrayOutputStream stream = new ByteArrayOutputStream();
                    stream.write(packageToSend, 0, FEATURE_RPT_DATA_SIZE);
                    stream.write(sequence | SLOT_WRITE_FLAG);
                    writeFeatureReport(stream.toByteArray());
                    bytesSent += FEATURE_RPT_SIZE;
                }
                sequence++;
            }
        } while (offset + FEATURE_RPT_DATA_SIZE <= bufferToSend.length);
	    return bytesSent;
    }

    /**
     * Read data from YubiKey
     * @return data that received
     * @throws IOException in case of communication error or no data was received
     */
    public byte[] receive(int expectedSize) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        // wait for
        stream.write(readFirstFeatureReport(), 0,  FEATURE_RPT_DATA_SIZE);

        // read data from device until we receive non-full packet/blob or unexpected sequence
        int sequence = 1;
        do {
            byte[] bufferRead = readFeatureReport();
            if ( (bufferRead[FEATURE_RPT_DATA_SIZE] & RESP_PENDING_FLAG) == RESP_PENDING_FLAG) {
                /* The lower five bits of the status byte has the response sequence
                 * number. If that gets reset to zero we are done.
                 */
                if ((bufferRead[FEATURE_RPT_DATA_SIZE] & 31) != sequence++) {
                    break;
                }
                stream.write(bufferRead, 0, FEATURE_RPT_DATA_SIZE);
            }
        } while ((sequence + 1) * FEATURE_RPT_DATA_SIZE <= SLOT_DATA_SIZE);

        // finished reading, reset state of YubiKey back to writing mode
        resetState();

        // parse received data and make sure it's proper checksum
        if (expectedSize > 0) {
            // received data should also contain 2 extra bytes (the CRC)
            expectedSize += 2;
            if (stream.size() < expectedSize) {
                throw new IOException("Received data only partially");
            }
            byte[] output = stream.toByteArray();
            if (!ChecksumUtils.checkCrc(output, expectedSize)) {
                throw new IOException("Error checksum of returned data");
            }
        }

        Logger.d(stream.size() + " bytes received over hid: " + StringUtils.bytesToHex(stream.toByteArray()));
        return stream.toByteArray();
    }

    /**
     * Reset the state of YubiKey from reading/means that there won't be any data returned
     */
    private void resetState() throws IOException {
        byte [] buffer = new byte[FEATURE_RPT_SIZE];
        buffer[FEATURE_RPT_SIZE - 1] = (byte)DUMMY_REPORT_WRITE; /* Invalid sequence = update only */
        writeFeatureReport(buffer);
    }

    /**
     * Wait for the Yubikey to clear the SLOT_WRITE_FLAG bits in mask.
     * Which means it's ready to receive new blob of data
     * @return true if it's allowed to send new blob of data, otherwise false
     * @throws IOException in case of communication error
     */
    private boolean isReadyToWrite() throws IOException  {
        long startTimestamp = System.currentTimeMillis();
        boolean isReadyToWrite = false;
        int sleepInterval = 1;
        do {
            // wait until we get flag cleared or it is timeouts
            byte[] featureReport = readFeatureReport();
            if ((featureReport[FEATURE_RPT_DATA_SIZE] & SLOT_WRITE_FLAG) == 0) {
                isReadyToWrite = true;
                break;
            }

            // throttling requests to device
            // if flag was not cleared we wait before checking status again
            sleepInterval = sleep(sleepInterval);
        } while (startTimestamp + WAIT_FOR_WRITE_FLAG_TIMEOUT < System.currentTimeMillis());
        return isReadyToWrite;
    }

    /**
     * Wait for YubiKey to notify that it has data to sent
     * @return first blob that received from YubiKey
     * @throws IOException in case of communication error
     */
    private byte[] readFirstFeatureReport() throws IOException  {
        // do/ while not timeout
        long startTimestamp = System.currentTimeMillis();
        boolean responseRequiresTimeExtension = false;
        // initial delay is 1 ms before checking status
        int sleepInterval = 1;
        int timeout = TIMEOUT;
        do {
            // wait before checking status,
            // because it takes some time for device to process received data and prepare data for output
            // also allows to control number of requests sent to YubiKey
            sleepInterval = sleep(sleepInterval);
            byte[] featureReport = readFeatureReport();
            if ( (featureReport[FEATURE_RPT_DATA_SIZE] & RESP_PENDING_FLAG) == RESP_PENDING_FLAG) {
                return featureReport;
            }
            // check if Yubikey says it will wait for user interaction than extend timeout
            // to allow user time to touch the button
            else if ((featureReport[FEATURE_RPT_DATA_SIZE] & RESP_TIMEOUT_WAIT_FLAG) == RESP_TIMEOUT_WAIT_FLAG
                    && !responseRequiresTimeExtension) {
                responseRequiresTimeExtension = true;
                timeout += 256 * TIMEOUT;
            }
        } while (startTimestamp + timeout > System.currentTimeMillis());

        resetState();
        if (responseRequiresTimeExtension) {
            throw new IOException("YubiKey timed out waiting for user interaction");
        } else {
            throw new NoDataException("YubiKey doesn't return any data within expected time frame");
        }
    }

    /**
     * Block the thread for some period of time and return valud of new interval for sleeping
     * @param sleepInterval timeout in milli seconds how long the thread will be sleeping
     * @return new interval (exponential increase until it reaches half of the second)
     */
    private int sleep(int sleepInterval) {
        try {
            Thread.sleep(sleepInterval);
            sleepInterval *= 2;
            if (sleepInterval > 500) {
                sleepInterval = 500;
            }
        } catch (InterruptedException ignore) {
        }
        return sleepInterval;
    }

    /**
     * Read single feature report
     * @return blob size of FEATURE_RPT_SIZE
     * @throws IOException
     */
    private byte[] readFeatureReport() throws IOException {
        byte[] bufferRead = new byte[FEATURE_RPT_SIZE];
        int bytesRead = connection.controlTransfer(UsbConstants.USB_DIR_IN | TYPE_CLASS | RECEIPIENT_INTERFACE, HID_GET_REPORT,
                REPORT_TYPE_FEATURE << 8, hidInterface.getId(), bufferRead, bufferRead.length, TIMEOUT);
        if (bytesRead < 0) {
            throw new IOException("Can't read the data");
        }
        if (bytesRead < FEATURE_RPT_SIZE) {
            throw new IOException("Size of blob is smaller than expected");
        }
        return bufferRead;
    }

    /**
     * Write single feature report
     * @param buffer blob size of FEATURE_RPT_SIZE
     */
    private void writeFeatureReport(byte[] buffer) throws IOException {
        int bytesSentPackage = connection.controlTransfer(
                UsbConstants.USB_DIR_OUT | TYPE_CLASS | RECEIPIENT_INTERFACE,
                HID_SET_REPORT, REPORT_TYPE_FEATURE << 8,
                hidInterface.getId(),
                buffer,
                buffer.length, TIMEOUT);
        if (bytesSentPackage < 0) {
            throw new IOException("Can't write the data");
        }
        if (bytesSentPackage < FEATURE_RPT_SIZE) {
            throw new IOException("Some of the data was not sent");
        }

    }

    /**
     * Checks if array of bytes only zeros
     * @param array buffer that gets checked
     * @return true if all zeros and false otherwise
     */
    private static boolean allZeros(byte[] array) {
        boolean isAllZeros = true;
        for (int i = 0; i < array.length; i++) {
            if (array[i] != 0) {
                isAllZeros = false;
                break;
            }
        }
        return isAllZeros;
    }

    /**
     * HID frame structure
     */
    private static class Frame {
        byte[] payload = new byte[SLOT_DATA_SIZE]; /* Frame payload */
        byte slot;                 /* Slot # field */
        short crc;                 /* CRC field */
        byte[] filler = new byte[3];            /* Filler */

        byte[] toByteArray() {
            ByteBuffer byteBuffer = ByteBuffer.allocate(SLOT_DATA_SIZE + 6);
            byteBuffer.put(payload);
            if (payload.length < SLOT_DATA_SIZE) {
                byteBuffer.put(new byte[SLOT_DATA_SIZE - payload.length], 0, SLOT_DATA_SIZE - payload.length);
            }
            byteBuffer.put(slot);
            // swap bytes for CRC (requires little endian byte order)
            byteBuffer.put(ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN).putShort(crc).array());
            byteBuffer.put(filler);
            return byteBuffer.array();
        }
    }
}

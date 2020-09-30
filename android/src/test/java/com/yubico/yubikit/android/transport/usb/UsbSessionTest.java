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
package com.yubico.yubikit.android.transport.usb;

import android.hardware.usb.*;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.smartcard.ApduResponse;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.util.StringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class UsbSessionTest {
    private static final byte[] RESET_REQUEST = byteArrayOfInts(new int[]{0x62, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    private static final byte[] ANSWER_TO_RESET = byteArrayOfInts(new int[]{0x80, 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0x3b, 0xfc, 0x13, 0, 0, 0x81, 0x31, 0xfe, 0x15, 0x59, 0x75, 0x62, 0x69, 0x6b, 0x65, 0x79, 0x4e, 0x45, 0x4f, 0x72, 0x33});

    private static final byte[] SELECT_REQUEST = byteArrayOfInts(new int[]{0x6f, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08});
    private static final byte[] SELECT_RESPONSE = byteArrayOfInts(new int[]{0x80, 0x15, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x90, 0x00});

    private static final byte[] PACKAGE_16_BYTES = byteArrayOfInts(new int[]{0x6f, 0x06, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    private static final byte[] PACKAGE_16_BYTES_RESPONSE = byteArrayOfInts(new int[]{0x80, 0x06, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0});

    private static final byte STATUS_TIME_EXTENSION = (byte) 0x80;
    private static final int STATUS_BYTE_POSISION = 7;
    private static final int ERROR_BYTE_POSITION = 8;
    private static final int CCID_HEADER_SIZE = 10;

    private static byte[] byteArrayOfInts(int[] ints) {
        byte[] bytes = new byte[ints.length];
        for (int i = 0; i < ints.length; i++) {
            bytes[i] = (byte) ints[i];
        }
        return bytes;
    }

    private SmartCardConnection usbConnection;
    private UsbYubiKeyDeviceMock mock = new UsbYubiKeyDeviceMock(Mockito.mock(UsbManager.class), Mockito.mock(UsbDevice.class));
    private Map<String, byte[]> commandResponses = new HashMap<>();

    @Before
    public void setUp() {
        commandResponses.put(StringUtils.bytesToHex(RESET_REQUEST), ANSWER_TO_RESET);
        commandResponses.put(StringUtils.bytesToHex(SELECT_REQUEST), SELECT_RESPONSE);
        commandResponses.put(StringUtils.bytesToHex(PACKAGE_16_BYTES), PACKAGE_16_BYTES_RESPONSE);
        mock.setResponseMap(commandResponses);
    }

    @Test
    public void connectAndReset() throws IOException {
        usbConnection = mock.openConnection(SmartCardConnection.class);
    }

    @Test
    public void executeCommand() throws IOException {
        byte[] selectPIVCommand = byteArrayOfInts(new int[]{0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08});
        usbConnection = mock.openConnection(SmartCardConnection.class);
        ApduResponse response = new ApduResponse(usbConnection.sendAndReceive(selectPIVCommand));
        byte[] selectPIVResponse = byteArrayOfInts(new int[]{0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x90, 0x00});
        Assert.assertEquals(SW.OK, response.getSw());
        Assert.assertArrayEquals(Arrays.copyOfRange(response.getBytes(), 0, response.getBytes().length - 2), response.getData());
        Assert.assertArrayEquals(selectPIVResponse, response.getBytes());
    }

    @Test
    public void executeCommandMultiplyOfPackageSize() throws IOException {
        byte[] alignedCommand = byteArrayOfInts(new int[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        usbConnection = mock.openConnection(SmartCardConnection.class);
        byte[] response = usbConnection.sendAndReceive(alignedCommand);
        Assert.assertNotNull(response);
    }

    @Test
    public void executeCommandWithExtendedWaiting() throws IOException {
        commandResponses.put(StringUtils.bytesToHex(PACKAGE_16_BYTES), changeByte(PACKAGE_16_BYTES_RESPONSE, STATUS_BYTE_POSISION, STATUS_TIME_EXTENSION));
        byte[] commandThatRequiresWaiting = byteArrayOfInts(new int[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        usbConnection = mock.openConnection(SmartCardConnection.class);
        usbConnection.sendAndReceive(commandThatRequiresWaiting);
    }

    @Test(expected = IOException.class)
    public void failToSend() throws IOException {
        mock.mockOutError();
        usbConnection = mock.openConnection(SmartCardConnection.class);
    }

    @Test(expected = IOException.class)
    public void failToRead() throws IOException {
        mock.mockInError();
        usbConnection = mock.openConnection(SmartCardConnection.class);
    }

    @Test(expected = IOException.class)
    public void readWithCCIDStatus() throws IOException {
        // change status flag to some value different from STATUS_TIME_EXTENSION
        commandResponses.put(StringUtils.bytesToHex(PACKAGE_16_BYTES), changeByte(PACKAGE_16_BYTES_RESPONSE, STATUS_BYTE_POSISION, (byte) 0x10));
        byte[] commandThatReturnsStatusCode = byteArrayOfInts(new int[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        usbConnection = mock.openConnection(SmartCardConnection.class);
        usbConnection.sendAndReceive(commandThatReturnsStatusCode);
    }

    @Test
    public void readWithCCIDErrorNoStatus() throws IOException {
        // change error flag to some value different from STATUS_TIME_EXTENSION
        // it will be ignored because status is 0
        commandResponses.put(StringUtils.bytesToHex(PACKAGE_16_BYTES), changeByte(PACKAGE_16_BYTES_RESPONSE, ERROR_BYTE_POSITION, (byte) 0x10));
        byte[] commandThatReturnsStatusCode = byteArrayOfInts(new int[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        usbConnection = mock.openConnection(SmartCardConnection.class);
        usbConnection.sendAndReceive(commandThatReturnsStatusCode);
    }

    @Test(expected = IOException.class)
    public void executeCommandWithEmptyResponse() throws IOException {
        byte[] unknownCommand = byteArrayOfInts(new int[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        usbConnection = mock.openConnection(SmartCardConnection.class);
        usbConnection.sendAndReceive(unknownCommand);
    }

    /**
     * Sets status byte to specific value
     *
     * @param input    initial array
     * @param position the position on byte needs to be changed
     * @param newValue new value of status byte
     * @return modified array
     */
    private static byte[] changeByte(byte[] input, int position, byte newValue) {
        byte[] output = Arrays.copyOf(input, input.length);
        output[position] = newValue;
        return output;
    }

    private static class UsbYubiKeyDeviceMock extends UsbYubiKeyDevice {
        final static int MAX_BLOB_SIZE = 16;
        final UsbDeviceConnection connection = Mockito.mock(UsbDeviceConnection.class);
        final UsbInterface usbInterface = Mockito.mock(UsbInterface.class);
        final UsbEndpoint endpointIn = Mockito.mock(UsbEndpoint.class);
        final UsbEndpoint endpointOut = Mockito.mock(UsbEndpoint.class);

        byte[] currentCommand;
        int blobOffset = 0;

        public UsbYubiKeyDeviceMock(UsbManager usbManager, UsbDevice usbDevice) {
            super(usbManager, usbDevice);
        }

        @Override
        public <T extends YubiKeyConnection> T openConnection(Class<T> connectionType) throws IOException {
            Mockito.when(connection.claimInterface(Mockito.any(), Mockito.anyBoolean())).thenReturn(true);
            return connectionType.cast(new UsbSmartCardConnection(getUsbDevice(), connection, usbInterface, endpointIn, endpointOut));
        }

        public void mockOutError() {
            Mockito.when(connection.bulkTransfer(
                    Mockito.any(UsbEndpoint.class),
                    Mockito.any(byte[].class),
                    Mockito.anyInt(),
                    Mockito.anyInt()
            )).thenReturn(-1);
        }

        public void mockInError() {
            Mockito.when(connection.bulkTransfer(
                    Mockito.any(UsbEndpoint.class),
                    Mockito.any(byte[].class),
                    Mockito.anyInt(),
                    Mockito.anyInt(),
                    Mockito.anyInt()
            )).thenReturn(-1);
        }

        public void setResponseMap(final Map<String, byte[]> map) {

            Mockito.when(connection.bulkTransfer(
                    Mockito.any(UsbEndpoint.class),
                    Mockito.any(byte[].class),
                    Mockito.anyInt(),
                    Mockito.anyInt(),
                    Mockito.anyInt()
            )).thenAnswer(new Answer<Integer>() {
                @Override
                public Integer answer(InvocationOnMock invocation) throws Throwable {
                    UsbEndpoint endpoint = invocation.getArgument(0);
                    byte[] buffer = invocation.getArgument(1);
                    int offset = invocation.getArgument(2);
                    int size = invocation.getArgument(3);
                    int timeout = invocation.getArgument(4);
                    currentCommand = buffer;
                    if (endpoint == endpointOut) {
                        blobOffset = 0;
                        return Math.min(size, MAX_BLOB_SIZE);
                    }
                    return -1;
                }
            });

            Mockito.when(endpointIn.getMaxPacketSize()).thenReturn(MAX_BLOB_SIZE);
            Mockito.when(endpointOut.getMaxPacketSize()).thenReturn(MAX_BLOB_SIZE);
            Mockito.when(connection.bulkTransfer(
                    Mockito.any(UsbEndpoint.class),
                    Mockito.any(byte[].class),
                    Mockito.anyInt(),
                    Mockito.anyInt()
            )).thenAnswer(new Answer<Integer>() {
                @Override
                public Integer answer(InvocationOnMock invocation) throws Throwable {
                    UsbEndpoint endpoint = invocation.getArgument(0);
                    byte[] buffer = invocation.getArgument(1);
                    int size = invocation.getArgument(2);
                    int timeout = invocation.getArgument(3);
                    if (endpoint == endpointIn) {
                        String request = StringUtils.bytesToHex(currentCommand);
                        byte[] response = map.get(request);
                        if (response == null) {
                            return 0;
                        } else if (response[STATUS_BYTE_POSISION] == STATUS_TIME_EXTENSION) {
                            // next response will be successful
                            map.put(request, changeByte(response, STATUS_BYTE_POSISION, (byte) 0));

                            int blobSize = Math.min(CCID_HEADER_SIZE, size);
                            System.arraycopy(response, blobOffset, buffer, 0, blobSize);
                            return blobSize;
                        }
                        int blobSize = Math.min(response.length - blobOffset, size);
                        System.arraycopy(response, blobOffset, buffer, 0, blobSize);
                        blobOffset += blobSize;
                        return blobSize;
                    }
                    return -1;
                }
            });
        }
    }
}

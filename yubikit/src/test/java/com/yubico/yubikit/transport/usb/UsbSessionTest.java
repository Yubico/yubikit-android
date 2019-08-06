package com.yubico.yubikit.transport.usb;

import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbManager;

import androidx.annotation.NonNull;

import com.yubico.yubikit.apdu.Apdu;
import com.yubico.yubikit.apdu.ApduResponse;
import com.yubico.yubikit.exceptions.YubikeyCommunicationException;
import com.yubico.yubikit.transport.Iso7816Connection;
import com.yubico.yubikit.utils.StringUtils;

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
    private static final short SUCCESS_CODE = (short)0x9000;

    private static final byte[] RESET_REQUEST = StringUtils.byteArrayOfInts(new int[] {0x62, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    private static final byte[] ANSWER_TO_RESET = StringUtils.byteArrayOfInts(new int[] {0x80, 0x16, 0, 0, 0, 0, 0, 0, 0, 0, 0x3b, 0xfc, 0x13, 0, 0, 0x81, 0x31, 0xfe, 0x15, 0x59, 0x75, 0x62, 0x69, 0x6b, 0x65, 0x79, 0x4e, 0x45 ,0x4f ,0x72, 0x33});

    private static final byte[] SELECT_REQUEST = StringUtils.byteArrayOfInts(new int[] {0x6f, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xa4, 0x04, 0x00, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08});
    private static final byte[] SELECT_RESPONSE = StringUtils.byteArrayOfInts(new int[] {0x80, 0x15, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x90, 0x00});

    private static final byte[] PACKAGE_16_BYTES = StringUtils.byteArrayOfInts(new int[] {0x6f, 0x06, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0});
    private static final byte[] PACKAGE_16_BYTES_RESPONSE = StringUtils.byteArrayOfInts(new int[] {0x80, 0x06, 0, 0, 0, 0, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0});

    private static final byte STATUS_TIME_EXTENSION = (byte) 0x80;
    private static final int STATUS_BYTE_POSISION = 7;
    private static final int ERROR_BYTE_POSITION = 8;
    private static final int CCID_HEADER_SIZE = 10;

    private Iso7816Connection usbConnection;
    private UsbSessionMock mock = new UsbSessionMock(Mockito.mock(UsbManager.class), Mockito.mock(UsbDevice.class));;
    private Map<String, byte[]> commandResponses = new HashMap<>();
    @Before
    public void setUp() {
        commandResponses.put(StringUtils.convertBytesToString(RESET_REQUEST), ANSWER_TO_RESET);
        commandResponses.put(StringUtils.convertBytesToString(SELECT_REQUEST), SELECT_RESPONSE);
        commandResponses.put(StringUtils.convertBytesToString(PACKAGE_16_BYTES), PACKAGE_16_BYTES_RESPONSE);
        mock.setResponseMap(commandResponses);
    }

    @Test
    public void connectAndReset() throws IOException {
        usbConnection = mock.openIso7816Connection();
    }

    @Test
    public void executeCommand() throws IOException {
        byte[] selectPIVCommand = StringUtils.byteArrayOfInts(new int[] {0x00, 0xA4, 0x04, 0x00, 0x05, 0xA0, 0x00, 0x00, 0x03, 0x08});
        usbConnection = mock.openIso7816Connection();
        byte[] atr = usbConnection.getAtr();
        Assert.assertNotNull(atr);
        ApduResponse response = usbConnection.execute(new Apdu(selectPIVCommand));
        byte[] selectPIVResponse = StringUtils.byteArrayOfInts(new int[] {0x61, 0x11, 0x4f, 0x06, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00, 0x79, 0x07, 0x4f, 0x05, 0xa0, 0x00, 0x00, 0x03, 0x08, 0x90, 0x00});
        Assert.assertTrue(response.hasStatusCode(SUCCESS_CODE));
        Assert.assertNotNull(response.responseData());
        Assert.assertArrayEquals(selectPIVResponse, response.getData());
    }

    @Test
    public void executeCommandMultiplyOfPackageSize() throws IOException {
        byte[] alignedCommand = StringUtils.byteArrayOfInts(new int[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        usbConnection = mock.openIso7816Connection();
        byte[] atr = usbConnection.getAtr();
        Assert.assertNotNull(atr);
        ApduResponse response = usbConnection.execute(new Apdu(alignedCommand));
        Assert.assertNotNull(response.getData());
    }

    @Test
    public void executeCommandWithExtendedWaiting() throws IOException {
        commandResponses.put(StringUtils.convertBytesToString(PACKAGE_16_BYTES), changeByte(PACKAGE_16_BYTES_RESPONSE, STATUS_BYTE_POSISION, STATUS_TIME_EXTENSION));
        byte[] commandThatRequiresWaiting = StringUtils.byteArrayOfInts(new int[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        usbConnection = mock.openIso7816Connection();
        usbConnection.getAtr();
        usbConnection.execute(new Apdu(commandThatRequiresWaiting));
    }

    @Test(expected = YubikeyCommunicationException.class)
    public void failToSend() throws IOException {
        mock.mockOutError();
        usbConnection = mock.openIso7816Connection();
        usbConnection.getAtr();
    }

    @Test(expected = YubikeyCommunicationException.class)
    public void failToRead() throws IOException  {
        mock.mockInError();
        usbConnection = mock.openIso7816Connection();
        usbConnection.getAtr();
    }

    @Test(expected = YubikeyCommunicationException.class)
    public void readWithCCIDStatus() throws IOException  {
        // change status flag to some value different from STATUS_TIME_EXTENSION
        commandResponses.put(StringUtils.convertBytesToString(PACKAGE_16_BYTES), changeByte(PACKAGE_16_BYTES_RESPONSE, STATUS_BYTE_POSISION, (byte)0x10));
        byte[] commandThatReturnsStatusCode = StringUtils.byteArrayOfInts(new int[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        usbConnection = mock.openIso7816Connection();
        usbConnection.getAtr();
        usbConnection.execute(new Apdu(commandThatReturnsStatusCode));
    }

    @Test
    public void readWithCCIDErrorNoStatus() throws IOException  {
        // change error flag to some value different from STATUS_TIME_EXTENSION
        // it will be ignored because status is 0
        commandResponses.put(StringUtils.convertBytesToString(PACKAGE_16_BYTES), changeByte(PACKAGE_16_BYTES_RESPONSE, ERROR_BYTE_POSITION, (byte)0x10));
        byte[] commandThatReturnsStatusCode = StringUtils.byteArrayOfInts(new int[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        usbConnection = mock.openIso7816Connection();
        usbConnection.getAtr();
        usbConnection.execute(new Apdu(commandThatReturnsStatusCode));
    }

    @Test(expected = YubikeyCommunicationException.class)
    public void executeCommandWithEmptyResponse() throws IOException {
        byte[] unknownCommand = StringUtils.byteArrayOfInts(new int[] {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00});
        usbConnection = mock.openIso7816Connection();
        usbConnection.getAtr();
        usbConnection.execute(new Apdu(unknownCommand));
    }

    /**
     * Sets status byte to specific value
     * @param input initial array
     * @param position the position on byte needs to be changed
     * @param newValue new value of status byte
     * @return modified array
     */
    private static byte[] changeByte(byte[] input, int position, byte newValue) {
        byte[] output = Arrays.copyOf(input, input.length);
        output[position] = newValue;
        return output;
    }

    private class UsbSessionMock extends UsbSession {
        final static int MAX_BLOB_SIZE = 16;
        final UsbDeviceConnection connection = Mockito.mock(UsbDeviceConnection.class);
        final UsbEndpoint endpointIn = Mockito.mock(UsbEndpoint.class);
        final UsbEndpoint endpointOut = Mockito.mock(UsbEndpoint.class);

        byte[] currentCommand;
        int blobOffset = 0;
        public UsbSessionMock(UsbManager usbManager, UsbDevice usbDevice) {
            super(usbManager, usbDevice);
        }

        @NonNull
        @Override
        public Iso7816Connection openIso7816Connection() throws YubikeyCommunicationException {
            return new UsbIso7816Connection(connection, endpointIn, endpointOut);
        }

        public void mockOutError(){
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
                        String request = StringUtils.convertBytesToString(currentCommand);
                        byte[] response = map.get(request);
                        if (response == null) {
                            return 0;
                        } else if (response[STATUS_BYTE_POSISION] == STATUS_TIME_EXTENSION) {
                            // next response will be successful
                            map.put(request, changeByte(response, STATUS_BYTE_POSISION, (byte)0));

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

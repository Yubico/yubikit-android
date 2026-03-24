/*
 * Copyright (C) 2026 Yubico.
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

package com.yubico.yubikit.android.transport.usb.connection;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import android.hardware.usb.UsbConstants;
import android.hardware.usb.UsbDevice;
import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import com.yubico.yubikit.Codec;
import java.io.IOException;
import org.junit.Before;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.mockito.invocation.InvocationOnMock;

/**
 * Unit tests for {@link FidoConnectionHandler}. Tests FIDO device detection via HID report
 * descriptor parsing and USB interface claiming.
 */
@RunWith(Enclosed.class)
public class FidoConnectionHandlerTest {

  // FIDO U2F HID Report Descriptor
  // Contains Usage Page (FIDO Alliance 0xF1D0) at bytes 0-2
  private static final String FIDO_REPORT_DESCRIPTOR_HEX =
      "06D0F1" + // Usage Page (FIDO Alliance 0xF1D0)
          "0901" + // Usage (U2F HID Authenticator Device)
          "A101" + // Collection (Application)
          "0920" + // Usage (Input Report Data)
          "1500" + // Logical Minimum (0)
          "26FF00" + // Logical Maximum (255)
          "7508" + // Report Size (8)
          "9540" + // Report Count (64)
          "8102" + // Input (Data, Var, Abs)
          "C0"; // End Collection

  // Generic Desktop Keyboard HID Report Descriptor (non-FIDO)
  private static final String NON_FIDO_REPORT_DESCRIPTOR_HEX =
      "0501" + // Usage Page (Generic Desktop)
          "0906" + // Usage (Keyboard)
          "A101" + // Collection (Application)
          "0507" + // Usage Page (Keyboard)
          "C0"; // End Collection

  // Convert to byte arrays for use in tests
  static final byte[] FIDO_REPORT_DESCRIPTOR = Codec.fromHex(FIDO_REPORT_DESCRIPTOR_HEX);
  static final byte[] NON_FIDO_REPORT_DESCRIPTOR = Codec.fromHex(NON_FIDO_REPORT_DESCRIPTOR_HEX);

  /**
   * Tests for {@link FidoConnectionHandler#hasFidoUsagePage(byte[])}.
   *
   * <p>Verifies detection of FIDO Alliance usage page (0xF1D0) in HID report descriptors. Tests
   * include:
   *
   * <ul>
   *   <li>Valid FIDO descriptors with pattern at different positions
   *   <li>Non-FIDO descriptors (wrong patterns, partial matches)
   *   <li>Edge cases (empty, too short, exact minimum size)
   * </ul>
   */
  public static class DescriptorPatternDetectionTests {

    @Test
    public void validDescriptor() {
      assertTrue(FidoConnectionHandler.hasFidoUsagePage(FIDO_REPORT_DESCRIPTOR));
    }

    @Test
    public void nonFidoDescriptor() {
      assertFalse(FidoConnectionHandler.hasFidoUsagePage(NON_FIDO_REPORT_DESCRIPTOR));
    }

    @Test
    public void emptyDescriptor() {
      assertFalse(FidoConnectionHandler.hasFidoUsagePage(new byte[0]));
    }

    @Test
    public void descriptorTooShort() {
      assertFalse(FidoConnectionHandler.hasFidoUsagePage(Codec.fromHex("06D0")));
    }

    @Test
    public void exactThreeBytes() {
      assertTrue(FidoConnectionHandler.hasFidoUsagePage(Codec.fromHex("06D0F1")));
    }

    @Test
    public void patternAtEnd() {
      byte[] descriptor = Codec.fromHex("000000" + "06D0F1");
      assertTrue(FidoConnectionHandler.hasFidoUsagePage(descriptor));
    }

    @Test
    public void patternInMiddle() {
      byte[] descriptor = Codec.fromHex("00" + "06D0F1" + "00");
      assertTrue(FidoConnectionHandler.hasFidoUsagePage(descriptor));
    }

    @Test
    public void partialMatch() {
      byte[] descriptor = Codec.fromHex("06D000"); // Wrong third byte
      assertFalse(FidoConnectionHandler.hasFidoUsagePage(descriptor));
    }

    @Test
    public void wrongTagByte() {
      byte[] descriptor = Codec.fromHex("05D0F1"); // Wrong first byte
      assertFalse(FidoConnectionHandler.hasFidoUsagePage(descriptor));
    }
  }

  /**
   * Base class providing common USB mock setup for interface and connection tests.
   *
   * <p>Provides mock objects for USB device, connection, interfaces, and endpoints, along with
   * helper methods for simulating HID descriptor responses.
   */
  public abstract static class UsbMockTestBase {

    protected FidoConnectionHandler handler;
    protected UsbDevice mockDevice;
    protected UsbDeviceConnection mockConnection;
    protected UsbInterface mockHidInterface;
    protected UsbInterface mockNonHidInterface;
    protected UsbEndpoint mockEndpointIn;
    protected UsbEndpoint mockEndpointOut;

    @Before
    public void setup() {
      handler = new FidoConnectionHandler();
      mockDevice = mock(UsbDevice.class);
      mockConnection = mock(UsbDeviceConnection.class);
      mockHidInterface = mock(UsbInterface.class);
      mockNonHidInterface = mock(UsbInterface.class);
      mockEndpointIn = mock(UsbEndpoint.class);
      mockEndpointOut = mock(UsbEndpoint.class);

      // Setup non-HID interface
      when(mockNonHidInterface.getInterfaceClass()).thenReturn(UsbConstants.USB_CLASS_MASS_STORAGE);
      when(mockNonHidInterface.getId()).thenReturn(0);

      // Setup HID interface
      when(mockHidInterface.getInterfaceClass()).thenReturn(UsbConstants.USB_CLASS_HID);
      when(mockHidInterface.getId()).thenReturn(1);
      when(mockHidInterface.getEndpointCount()).thenReturn(2);
      when(mockHidInterface.getEndpoint(0)).thenReturn(mockEndpointIn);
      when(mockHidInterface.getEndpoint(1)).thenReturn(mockEndpointOut);

      // Setup endpoints
      when(mockEndpointIn.getType()).thenReturn(UsbConstants.USB_ENDPOINT_XFER_INT);
      when(mockEndpointIn.getDirection()).thenReturn(UsbConstants.USB_DIR_IN);
      when(mockEndpointOut.getType()).thenReturn(UsbConstants.USB_ENDPOINT_XFER_INT);
      when(mockEndpointOut.getDirection()).thenReturn(UsbConstants.USB_DIR_OUT);
    }

    /**
     * Configures mockConnection to return FIDO report descriptor when controlTransfer is called.
     */
    protected void mockFidoReportDescriptor() {
      when(mockConnection.controlTransfer(
              anyInt(), anyInt(), anyInt(), anyInt(), any(byte[].class), anyInt(), anyInt()))
          .thenAnswer(invocation -> mockControlTransfer(invocation, FIDO_REPORT_DESCRIPTOR));
    }

    /**
     * Configures mockConnection to return non-FIDO report descriptor when controlTransfer is
     * called.
     */
    protected void mockNonFidoReportDescriptor() {
      when(mockConnection.controlTransfer(
              anyInt(), anyInt(), anyInt(), anyInt(), any(byte[].class), anyInt(), anyInt()))
          .thenAnswer(invocation -> mockControlTransfer(invocation, NON_FIDO_REPORT_DESCRIPTOR));
    }

    /** Mock implementation of USB control transfer for HID descriptor reading. */
    protected int mockControlTransfer(InvocationOnMock invocation, byte[] reportDescriptor) {
      byte[] buffer = invocation.getArgument(4);
      int wValue = invocation.getArgument(2);
      int descriptorType = wValue >> 8;

      if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE) {
        buffer[7] = (byte) (reportDescriptor.length & 0xFF);
        buffer[8] = (byte) ((reportDescriptor.length >> 8) & 0xFF);
        return FidoConnectionHandler.HID_DESCRIPTOR_SIZE;
      } else if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE_REPORT) {
        System.arraycopy(
            reportDescriptor, 0, buffer, 0, Math.min(reportDescriptor.length, buffer.length));
        return reportDescriptor.length;
      }
      return -1;
    }

    /** Mock control transfer for a specific interface ID with specific descriptor. */
    protected void mockControlTransferForInterface(int interfaceId, byte[] reportDescriptor) {
      when(mockConnection.controlTransfer(
              anyInt(), anyInt(), anyInt(), eq(interfaceId), any(byte[].class), anyInt(), anyInt()))
          .thenAnswer(
              invocation -> {
                byte[] buffer = invocation.getArgument(4);
                int wValue = invocation.getArgument(2);
                int descriptorType = wValue >> 8;

                if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE) {
                  buffer[7] = (byte) (reportDescriptor.length & 0xFF);
                  buffer[8] = (byte) ((reportDescriptor.length >> 8) & 0xFF);
                  return FidoConnectionHandler.HID_DESCRIPTOR_SIZE;
                } else if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE_REPORT) {
                  System.arraycopy(
                      reportDescriptor,
                      0,
                      buffer,
                      0,
                      Math.min(reportDescriptor.length, buffer.length));
                  return reportDescriptor.length;
                }
                return -1;
              });
    }
  }

  /**
   * Tests for {@link FidoConnectionHandler#getClaimedInterface(UsbDevice, UsbDeviceConnection)}.
   *
   * <p>Verifies USB interface discovery, claiming, and validation logic including:
   *
   * <ul>
   *   <li>Finding FIDO interfaces among multiple USB interfaces
   *   <li>Skipping non-HID interfaces
   *   <li>Releasing non-FIDO interfaces
   *   <li>Error handling for descriptor read failures
   *   <li>Interface retry logic when claiming fails
   * </ul>
   */
  public static class InterfaceClaimingTests extends UsbMockTestBase {

    @Test
    public void findsFidoInterface() throws IOException {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);
      mockFidoReportDescriptor();

      UsbInterface result = handler.getClaimedInterface(mockDevice, mockConnection);

      assertNotNull(result);
      assertEquals(mockHidInterface, result);
      verify(mockConnection).claimInterface(mockHidInterface, true);
      verify(mockConnection, never()).releaseInterface(mockHidInterface);
    }

    @Test
    public void skipsNonHidInterface() throws IOException {
      when(mockDevice.getInterfaceCount()).thenReturn(2);
      when(mockDevice.getInterface(0)).thenReturn(mockNonHidInterface);
      when(mockDevice.getInterface(1)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);
      mockFidoReportDescriptor();

      UsbInterface result = handler.getClaimedInterface(mockDevice, mockConnection);

      assertNotNull(result);
      assertEquals(mockHidInterface, result);
      verify(mockConnection, never()).claimInterface(mockNonHidInterface, true);
    }

    @Test
    public void releasesNonFidoInterface() {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);
      mockNonFidoReportDescriptor();

      assertThrows(
          IllegalStateException.class,
          () -> handler.getClaimedInterface(mockDevice, mockConnection));

      verify(mockConnection, times(1)).claimInterface(mockHidInterface, true);
      verify(mockConnection, times(1)).releaseInterface(mockHidInterface);
    }

    @Test
    public void noInterfacesThrows() {
      when(mockDevice.getInterfaceCount()).thenReturn(0);

      IllegalStateException exception =
          assertThrows(
              IllegalStateException.class,
              () -> handler.getClaimedInterface(mockDevice, mockConnection));

      assertEquals("No HID interface with FIDO usage page found", exception.getMessage());
    }

    @Test
    public void claimFailureRetries() throws IOException {
      UsbInterface mockSecondHidInterface = mock(UsbInterface.class);
      when(mockSecondHidInterface.getInterfaceClass()).thenReturn(UsbConstants.USB_CLASS_HID);
      when(mockSecondHidInterface.getId()).thenReturn(2);
      when(mockSecondHidInterface.getEndpointCount()).thenReturn(2);
      when(mockSecondHidInterface.getEndpoint(0)).thenReturn(mockEndpointIn);
      when(mockSecondHidInterface.getEndpoint(1)).thenReturn(mockEndpointOut);

      when(mockDevice.getInterfaceCount()).thenReturn(2);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getInterface(1)).thenReturn(mockSecondHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");

      // First interface claim fails, second succeeds
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(false);
      when(mockConnection.claimInterface(mockSecondHidInterface, true)).thenReturn(true);
      mockFidoReportDescriptor();

      UsbInterface result = handler.getClaimedInterface(mockDevice, mockConnection);

      assertEquals(mockSecondHidInterface, result);
      verify(mockConnection, times(1)).claimInterface(mockHidInterface, true);
      verify(mockConnection, times(1)).claimInterface(mockSecondHidInterface, true);
      verify(mockConnection, never()).releaseInterface(mockSecondHidInterface);
    }

    @Test
    public void readFailureThrows() {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);

      // Mock control transfer to fail for report descriptor
      when(mockConnection.controlTransfer(
              anyInt(), anyInt(), anyInt(), anyInt(), any(byte[].class), anyInt(), anyInt()))
          .thenReturn(-1);

      assertThrows(
          IOException.class, () -> handler.getClaimedInterface(mockDevice, mockConnection));

      verify(mockConnection).releaseInterface(mockHidInterface);
    }

    @Test
    public void emptyDescriptorThrows() {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);

      // Mock control transfer to return empty report descriptor
      when(mockConnection.controlTransfer(
              anyInt(), anyInt(), anyInt(), anyInt(), any(byte[].class), anyInt(), anyInt()))
          .thenAnswer(
              invocation -> {
                int wValue = invocation.getArgument(2);
                int descriptorType = wValue >> 8;

                if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE) {
                  return FidoConnectionHandler.HID_DESCRIPTOR_SIZE;
                } else if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE_REPORT) {
                  return 0; // Empty descriptor
                }
                return -1;
              });

      IOException exception =
          assertThrows(
              IOException.class, () -> handler.getClaimedInterface(mockDevice, mockConnection));

      assertEquals("Received empty report descriptor", exception.getMessage());
      verify(mockConnection).releaseInterface(mockHidInterface);
    }

    @Test
    public void hidSucceedsReportFails() {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);

      // Mock: HID descriptor succeeds, but report descriptor fails
      when(mockConnection.controlTransfer(
              anyInt(), anyInt(), anyInt(), anyInt(), any(byte[].class), anyInt(), anyInt()))
          .thenAnswer(
              invocation -> {
                byte[] buffer = invocation.getArgument(4);
                int wValue = invocation.getArgument(2);
                int descriptorType = wValue >> 8;

                if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE) {
                  buffer[7] = 0x20; // length = 32
                  buffer[8] = 0x00;
                  return FidoConnectionHandler.HID_DESCRIPTOR_SIZE;
                } else if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE_REPORT) {
                  return -1;
                }
                return -1;
              });

      assertThrows(
          IOException.class, () -> handler.getClaimedInterface(mockDevice, mockConnection));

      verify(mockConnection).releaseInterface(mockHidInterface);
    }

    @Test
    public void findsCorrectInMultipleInterfaces() throws IOException {
      UsbInterface mockNonFidoHidInterface = mock(UsbInterface.class);
      when(mockNonFidoHidInterface.getInterfaceClass()).thenReturn(UsbConstants.USB_CLASS_HID);
      when(mockNonFidoHidInterface.getId()).thenReturn(0);

      when(mockDevice.getInterfaceCount()).thenReturn(2);
      when(mockDevice.getInterface(0)).thenReturn(mockNonFidoHidInterface);
      when(mockDevice.getInterface(1)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockNonFidoHidInterface, true)).thenReturn(true);
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);

      // Mock different descriptors for different interfaces
      mockControlTransferForInterface(0, NON_FIDO_REPORT_DESCRIPTOR);
      mockControlTransferForInterface(1, FIDO_REPORT_DESCRIPTOR);

      UsbInterface result = handler.getClaimedInterface(mockDevice, mockConnection);

      assertNotNull(result);
      assertEquals(mockHidInterface, result);
      // First interface should be released since it's not FIDO
      verify(mockConnection).releaseInterface(mockNonFidoHidInterface);
      // Second interface should not be released since it's being returned
      verify(mockConnection, never()).releaseInterface(mockHidInterface);
    }

    @Test
    public void exceptionPropagates() {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);

      // Mock: controlTransfer THROWS exception during report descriptor read
      when(mockConnection.controlTransfer(
              anyInt(), anyInt(), anyInt(), anyInt(), any(byte[].class), anyInt(), anyInt()))
          .thenAnswer(
              invocation -> {
                int wValue = invocation.getArgument(2);
                int descriptorType = wValue >> 8;

                if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE) {
                  // HID descriptor succeeds
                  byte[] buffer = invocation.getArgument(4);
                  buffer[7] = 0x20;
                  buffer[8] = 0x00;
                  return FidoConnectionHandler.HID_DESCRIPTOR_SIZE;
                } else if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE_REPORT) {
                  // Report descriptor read THROWS
                  throw new RuntimeException("USB device disconnected");
                }
                return -1;
              });

      // Should propagate the exception (wrapped or unwrapped)
      assertThrows(Exception.class, () -> handler.getClaimedInterface(mockDevice, mockConnection));

      // Verify interface was released in finally block
      verify(mockConnection).releaseInterface(mockHidInterface);
    }
  }

  /**
   * Tests for fallback behavior when HID descriptor read fails.
   *
   * <p>When the HID descriptor cannot be read to determine report descriptor size, the handler
   * falls back to a default buffer size. These tests verify:
   *
   * <ul>
   *   <li>Successful fallback when HID descriptor read fails but report descriptor succeeds
   *   <li>Proper error handling when both reads fail
   *   <li>Correct buffer size usage in fallback mode
   * </ul>
   */
  public static class FallbackBufferHandlingTests extends UsbMockTestBase {

    @Test
    public void fallbackFindsFido() throws IOException {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);

      // Mock control transfer - first call (HID descriptor) fails, second (report descriptor)
      // succeeds
      when(mockConnection.controlTransfer(
              anyInt(), anyInt(), anyInt(), anyInt(), any(byte[].class), anyInt(), anyInt()))
          .thenAnswer(
              invocation -> {
                byte[] buffer = invocation.getArgument(4);
                int wValue = invocation.getArgument(2);
                int bufferLength = invocation.getArgument(5);
                int descriptorType = wValue >> 8;

                if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE) {
                  // Fail HID descriptor read to trigger default buffer size
                  return 0;
                } else if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE_REPORT) {
                  // Verify we're using DEFAULT_REPORT_DESC_SIZE
                  assertEquals(FidoConnectionHandler.DEFAULT_REPORT_DESC_SIZE, bufferLength);
                  System.arraycopy(
                      FIDO_REPORT_DESCRIPTOR,
                      0,
                      buffer,
                      0,
                      Math.min(FIDO_REPORT_DESCRIPTOR.length, buffer.length));
                  return FIDO_REPORT_DESCRIPTOR.length;
                }
                return -1;
              });

      UsbInterface result = handler.getClaimedInterface(mockDevice, mockConnection);

      assertNotNull(result);
      assertEquals(mockHidInterface, result);
    }

    @Test
    public void fallbackFindsNonFido() {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);

      // Mock control transfer - HID descriptor read fails, report descriptor returns non-FIDO
      when(mockConnection.controlTransfer(
              anyInt(), anyInt(), anyInt(), anyInt(), any(byte[].class), anyInt(), anyInt()))
          .thenAnswer(
              invocation -> {
                byte[] buffer = invocation.getArgument(4);
                int wValue = invocation.getArgument(2);
                int bufferLength = invocation.getArgument(5);
                int descriptorType = wValue >> 8;

                if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE) {
                  // Fail HID descriptor read - triggers fallback
                  return 0;
                } else if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE_REPORT) {
                  // Verify we're using DEFAULT_REPORT_DESC_SIZE
                  assertEquals(FidoConnectionHandler.DEFAULT_REPORT_DESC_SIZE, bufferLength);
                  // Return NON-FIDO descriptor
                  System.arraycopy(
                      NON_FIDO_REPORT_DESCRIPTOR,
                      0,
                      buffer,
                      0,
                      Math.min(NON_FIDO_REPORT_DESCRIPTOR.length, buffer.length));
                  return NON_FIDO_REPORT_DESCRIPTOR.length;
                }
                return -1;
              });

      // Should throw because no FIDO interface found
      assertThrows(
          IllegalStateException.class,
          () -> handler.getClaimedInterface(mockDevice, mockConnection));

      // Verify interface was released
      verify(mockConnection, times(1)).claimInterface(mockHidInterface, true);
      verify(mockConnection, times(1)).releaseInterface(mockHidInterface);
    }

    @Test
    public void fallbackAlsoFails() {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);

      // Mock control transfer - both HID descriptor and report descriptor fail
      when(mockConnection.controlTransfer(
              anyInt(), anyInt(), anyInt(), anyInt(), any(byte[].class), anyInt(), anyInt()))
          .thenAnswer(
              invocation -> {
                int wValue = invocation.getArgument(2);
                int descriptorType = wValue >> 8;

                if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE) {
                  // Fail HID descriptor read
                  return 0;
                } else if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE_REPORT) {
                  // Fail report descriptor read too
                  return -1;
                }
                return -1;
              });

      // Should throw IOException
      assertThrows(
          IOException.class, () -> handler.getClaimedInterface(mockDevice, mockConnection));

      // Verify interface was released even though exceptions occurred
      verify(mockConnection, times(1)).claimInterface(mockHidInterface, true);
      verify(mockConnection, times(1)).releaseInterface(mockHidInterface);
    }

    @Test
    public void fallbackReturnsEmpty() {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);

      // Mock control transfer - HID descriptor fails, report descriptor returns empty
      when(mockConnection.controlTransfer(
              anyInt(), anyInt(), anyInt(), anyInt(), any(byte[].class), anyInt(), anyInt()))
          .thenAnswer(
              invocation -> {
                int wValue = invocation.getArgument(2);
                int bufferLength = invocation.getArgument(5);
                int descriptorType = wValue >> 8;

                if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE) {
                  // Fail HID descriptor read
                  return 0;
                } else if (descriptorType == FidoConnectionHandler.HID_DESCRIPTOR_TYPE_REPORT) {
                  // Verify fallback size
                  assertEquals(FidoConnectionHandler.DEFAULT_REPORT_DESC_SIZE, bufferLength);
                  // Return empty descriptor
                  return 0;
                }
                return -1;
              });

      // Should throw IOException for empty descriptor
      assertThrows(
          IOException.class, () -> handler.getClaimedInterface(mockDevice, mockConnection));

      // Verify interface was released
      verify(mockConnection, times(1)).claimInterface(mockHidInterface, true);
      verify(mockConnection, times(1)).releaseInterface(mockHidInterface);
    }
  }

  /**
   * Tests for {@link FidoConnectionHandler#createConnection(UsbDevice, UsbDeviceConnection)}.
   *
   * <p>Verifies USB FIDO connection creation with endpoint validation including:
   *
   * <ul>
   *   <li>Successful connection creation with valid FIDO interface
   *   <li>Finding interrupt endpoints among mixed endpoint types
   *   <li>Handling endpoint order variations
   *   <li>Error cases with missing or insufficient endpoints
   * </ul>
   */
  @SuppressWarnings("resource")
  public static class ConnectionCreationTests extends UsbMockTestBase {

    @Test
    public void createsConnection() throws IOException {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);
      mockFidoReportDescriptor();

      UsbFidoConnection connection = handler.createConnection(mockDevice, mockConnection);

      assertNotNull(connection);
    }

    @Test
    public void findsInterruptEndpoints() throws IOException {
      // Create additional endpoints with wrong types
      UsbEndpoint mockBulkEndpoint = mock(UsbEndpoint.class);
      UsbEndpoint mockControlEndpoint = mock(UsbEndpoint.class);

      when(mockBulkEndpoint.getType()).thenReturn(UsbConstants.USB_ENDPOINT_XFER_BULK);
      when(mockControlEndpoint.getType()).thenReturn(UsbConstants.USB_ENDPOINT_XFER_CONTROL);

      // Setup interface with 4 endpoints: bulk, interrupt IN, control, interrupt OUT
      when(mockHidInterface.getEndpointCount()).thenReturn(4);
      when(mockHidInterface.getEndpoint(0)).thenReturn(mockBulkEndpoint);
      when(mockHidInterface.getEndpoint(1)).thenReturn(mockEndpointIn);
      when(mockHidInterface.getEndpoint(2)).thenReturn(mockControlEndpoint);
      when(mockHidInterface.getEndpoint(3)).thenReturn(mockEndpointOut);

      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);

      mockFidoReportDescriptor();

      // Should successfully find the interrupt endpoints despite other types present
      UsbFidoConnection connection = handler.createConnection(mockDevice, mockConnection);

      assertNotNull(connection);
    }

    @Test
    public void endpointsInReverseOrder() throws IOException {
      // Setup endpoints in reverse order: OUT first, then IN
      when(mockHidInterface.getEndpointCount()).thenReturn(2);
      when(mockHidInterface.getEndpoint(0)).thenReturn(mockEndpointOut); // OUT first
      when(mockHidInterface.getEndpoint(1)).thenReturn(mockEndpointIn); // IN second

      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);

      mockFidoReportDescriptor();

      UsbFidoConnection connection = handler.createConnection(mockDevice, mockConnection);

      assertNotNull(connection);
    }

    @Test
    public void noEndpointsThrows() {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);
      when(mockHidInterface.getEndpointCount()).thenReturn(0);

      mockFidoReportDescriptor();

      assertThrows(
          NullPointerException.class, () -> handler.createConnection(mockDevice, mockConnection));
    }

    @Test
    public void singleEndpointThrows() {
      when(mockDevice.getInterfaceCount()).thenReturn(1);
      when(mockDevice.getInterface(0)).thenReturn(mockHidInterface);
      when(mockDevice.getDeviceName()).thenReturn("TestDevice");
      when(mockConnection.claimInterface(mockHidInterface, true)).thenReturn(true);
      when(mockHidInterface.getEndpointCount()).thenReturn(1);
      when(mockHidInterface.getEndpoint(0)).thenReturn(mockEndpointIn);

      mockFidoReportDescriptor();

      assertThrows(
          NullPointerException.class, () -> handler.createConnection(mockDevice, mockConnection));
    }
  }
}

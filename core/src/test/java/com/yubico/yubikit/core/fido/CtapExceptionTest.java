/*
 * Copyright (C) 2025 Yubico.
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

import static org.junit.Assert.*;

import org.junit.Test;

public class CtapExceptionTest {
  @Test
  public void testKnownErrorCode() {
    CtapException ex = new CtapException(CtapException.ERR_INVALID_COMMAND);
    assertEquals(CtapException.ERR_INVALID_COMMAND, ex.getCtapError());
    assertEquals("INVALID_COMMAND", ex.getErrorName());
    assertTrue(ex.getMessage().contains("INVALID_COMMAND"));
    assertTrue(ex.getMessage().contains("0x01"));
  }

  @Test
  public void testUnknownErrorCode() {
    // Test unknown error in the middle of spec range
    byte unknown = (byte) 0x55;
    CtapException ex = new CtapException(unknown);
    assertEquals(unknown, ex.getCtapError());
    assertEquals("UNKNOWN", ex.getErrorName());
    assertTrue(ex.getMessage().contains("UNKNOWN"));
    assertTrue(ex.getMessage().contains("0x55"));

    // Test unknown error at ERR_SPEC_LAST boundary
    byte unknownAtBoundary = CtapException.ERR_SPEC_LAST;
    CtapException exAtBoundary = new CtapException(unknownAtBoundary);
    assertEquals(unknownAtBoundary, exAtBoundary.getCtapError());
    assertEquals("UNKNOWN", exAtBoundary.getErrorName());
    assertTrue(exAtBoundary.getMessage().contains("UNKNOWN"));
    assertTrue(exAtBoundary.getMessage().contains("0xdf"));

    // Test unknown error just before ERR_SPEC_LAST
    byte unknownBeforeBoundary = (byte) 0xDE;
    CtapException exBeforeBoundary = new CtapException(unknownBeforeBoundary);
    assertEquals(unknownBeforeBoundary, exBeforeBoundary.getCtapError());
    assertEquals("UNKNOWN", exBeforeBoundary.getErrorName());
    assertTrue(exBeforeBoundary.getMessage().contains("UNKNOWN"));
    assertTrue(exBeforeBoundary.getMessage().contains("0xde"));
  }

  @Test
  public void testExtensionErrorCode() {
    // Test extension range boundary - first
    byte extensionFirst = CtapException.ERR_EXTENSION_FIRST;
    CtapException exFirst = new CtapException(extensionFirst);
    assertEquals(extensionFirst, exFirst.getCtapError());
    assertEquals("EXTENSION_ERROR", exFirst.getErrorName());
    assertTrue(exFirst.getMessage().contains("EXTENSION_ERROR"));
    assertTrue(exFirst.getMessage().contains("0xe0"));

    // Test extension range middle
    byte extension = (byte) 0xE1;
    CtapException ex = new CtapException(extension);
    assertEquals(extension, ex.getCtapError());
    assertEquals("EXTENSION_ERROR", ex.getErrorName());
    assertTrue(ex.getMessage().contains("EXTENSION_ERROR"));
    assertTrue(ex.getMessage().contains("0xe1"));

    // Test extension range boundary - last
    byte extensionLast = CtapException.ERR_EXTENSION_LAST;
    CtapException exLast = new CtapException(extensionLast);
    assertEquals(extensionLast, exLast.getCtapError());
    assertEquals("EXTENSION_ERROR", exLast.getErrorName());
    assertTrue(exLast.getMessage().contains("EXTENSION_ERROR"));
    assertTrue(exLast.getMessage().contains("0xef"));
  }

  @Test
  public void testVendorErrorCode() {
    // Test vendor range boundary - first
    byte vendorFirst = CtapException.ERR_VENDOR_FIRST;
    CtapException exFirst = new CtapException(vendorFirst);
    assertEquals(vendorFirst, exFirst.getCtapError());
    assertEquals("VENDOR_ERROR", exFirst.getErrorName());
    assertTrue(exFirst.getMessage().contains("VENDOR_ERROR"));
    assertTrue(exFirst.getMessage().contains("0xf0"));

    // Test vendor range middle
    byte vendor = (byte) 0xF2;
    CtapException ex = new CtapException(vendor);
    assertEquals(vendor, ex.getCtapError());
    assertEquals("VENDOR_ERROR", ex.getErrorName());
    assertTrue(ex.getMessage().contains("VENDOR_ERROR"));
    assertTrue(ex.getMessage().contains("0xf2"));

    // Test vendor range boundary - last
    byte vendorLast = CtapException.ERR_VENDOR_LAST;
    CtapException exLast = new CtapException(vendorLast);
    assertEquals(vendorLast, exLast.getCtapError());
    assertEquals("VENDOR_ERROR", exLast.getErrorName());
    assertTrue(exLast.getMessage().contains("VENDOR_ERROR"));
    assertTrue(exLast.getMessage().contains("0xff"));
  }

  @Test
  public void testAllKnownErrorNames() {
    // Spot check a few known error codes
    assertEquals("SUCCESS", new CtapException(CtapException.ERR_SUCCESS).getErrorName());
    assertEquals(
        "INVALID_PARAMETER", new CtapException(CtapException.ERR_INVALID_PARAMETER).getErrorName());
    assertEquals("TIMEOUT", new CtapException(CtapException.ERR_TIMEOUT).getErrorName());
    assertEquals("PIN_INVALID", new CtapException(CtapException.ERR_PIN_INVALID).getErrorName());
    assertEquals("OTHER", new CtapException(CtapException.ERR_OTHER).getErrorName());
    assertEquals("INVALID_CBOR", new CtapException(CtapException.ERR_INVALID_CBOR).getErrorName());
    assertEquals(
        "PIN_POLICY_VIOLATION",
        new CtapException(CtapException.ERR_PIN_POLICY_VIOLATION).getErrorName());
  }
}

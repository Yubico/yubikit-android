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

package com.yubico.yubikit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.util.Callback;
import com.yubico.yubikit.core.util.Result;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.Test;

/**
 * Covers the contract that decides whether a YubiKey may be used by the integration tests. A
 * regression here either bricks a key that should have been rejected, or kills the test process.
 */
public class AllowListTest {

  private static final String NO_LIST = "no allow list";

  private static class FakeProvider implements AllowList.AllowListProvider {
    private final List<Integer> serials;

    FakeProvider(List<Integer> serials) {
      this.serials = serials;
    }

    @Override
    public List<Integer> getList() {
      return serials;
    }

    @Override
    public String onInvalidInputErrorMessage() {
      return NO_LIST;
    }

    @Override
    public String onNotAllowedErrorMessage(Integer serialNumber) {
      return "not allowed: " + serialNumber;
    }
  }

  /**
   * Answers "file not found" to every APDU, so no applet can be selected. That is how a FIDO-only
   * Security Key presents over NFC, and it makes readInfo give up with an IllegalArgumentException,
   * which AllowList maps to serial number 0.
   */
  private static class SerialLessNfcConnection implements SmartCardConnection {
    @Override
    public byte[] sendAndReceive(byte[] apdu) {
      return new byte[] {0x6a, (byte) 0x82}; // SW_FILE_NOT_FOUND
    }

    @Override
    public Transport getTransport() {
      return Transport.NFC;
    }

    @Override
    public boolean isExtendedLengthApduSupported() {
      return false;
    }

    @Override
    public byte[] getAtr() {
      return new byte[0];
    }

    @Override
    public void close() {}
  }

  /** A key with no serial number, reachable only over NFC. */
  private static class SerialLessDevice implements YubiKeyDevice {
    @Override
    public Transport getTransport() {
      return Transport.NFC;
    }

    @Override
    public boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType) {
      return connectionType.isAssignableFrom(SmartCardConnection.class);
    }

    @Override
    public <T extends YubiKeyConnection> void requestConnection(
        Class<T> connectionType, Callback<Result<T, IOException>> callback) {
      throw new UnsupportedOperationException();
    }

    @Override
    public <T extends YubiKeyConnection> T openConnection(Class<T> connectionType) {
      return connectionType.cast(new SerialLessNfcConnection());
    }
  }

  /** Supports no connection type, so the serial number cannot be read and resolves to null. */
  private static class UnreadableDevice implements YubiKeyDevice {
    @Override
    public Transport getTransport() {
      return Transport.USB;
    }

    @Override
    public boolean supportsConnection(Class<? extends YubiKeyConnection> connectionType) {
      return false;
    }

    @Override
    public <T extends YubiKeyConnection> void requestConnection(
        Class<T> connectionType, Callback<Result<T, IOException>> callback) {
      throw new UnsupportedOperationException();
    }

    @Override
    public <T extends YubiKeyConnection> T openConnection(Class<T> connectionType) {
      throw new UnsupportedOperationException();
    }
  }

  private static AllowList allowListOf(Integer... serials) {
    return new AllowList(new FakeProvider(Arrays.asList(serials)));
  }

  private static AllowList emptyAllowList() {
    return new AllowList(new FakeProvider(Collections.emptyList()));
  }

  /** The whole point of deferring the check: a missing file must not stop construction. */
  @Test
  public void constructionSucceedsWithNoSerials() {
    emptyAllowList();
  }

  @Test
  public void emptyListIsReportedAsMissingConfiguration() {
    AssertionError error =
        assertThrows(
            AssertionError.class, () -> emptyAllowList().verify(new UnreadableDevice(), null));

    assertEquals(NO_LIST, error.getMessage());
  }

  /**
   * The serial check below deliberately skips UsbPid.OTHER, so the empty-list check has to be
   * unconditional or a missing allow list would silently admit those devices.
   */
  @Test
  public void emptyListIsRejectedEvenForOtherPid() {
    AssertionError error =
        assertThrows(
            AssertionError.class,
            () -> emptyAllowList().verify(new UnreadableDevice(), UsbPid.OTHER));

    assertEquals(NO_LIST, error.getMessage());
  }

  /**
   * A key with no serial number resolves to 0, so 0 is what admits Security Keys. Distinct from a
   * serial that could not be read at all, which resolves to null - see {@link
   * #unreadableSerialIsRejected()}.
   */
  @Test
  public void serialLessKeyIsAllowedByZeroEntry() {
    allowListOf(0).verify(new SerialLessDevice(), null);
  }

  @Test
  public void serialLessKeyIsRejectedWithoutZeroEntry() {
    AssertionError error =
        assertThrows(
            AssertionError.class, () -> allowListOf(1234567).verify(new SerialLessDevice(), null));

    assertEquals("not allowed: 0", error.getMessage());
  }

  /** A serial that could not be read at all must fail closed, not be waved through. */
  @Test
  public void unreadableSerialIsRejected() {
    AssertionError error =
        assertThrows(
            AssertionError.class,
            () -> allowListOf(1234567).verify(new UnreadableDevice(), UsbPid.YK4_OTP_FIDO_CCID));

    assertEquals("not allowed: null", error.getMessage());
  }

  /** With a populated list, UsbPid.OTHER bypasses the serial check, as before. */
  @Test
  public void otherPidBypassesSerialCheckWhenListIsPopulated() {
    allowListOf(1234567).verify(new UnreadableDevice(), UsbPid.OTHER);
  }
}

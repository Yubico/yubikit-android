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

package com.yubico.yubikit.core;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertTrue;

import android.hardware.usb.UsbDevice;
import com.yubico.yubikit.AlwaysManualTest;
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduFormat;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.framework.YkInstrumentedTests;
import com.yubico.yubikit.management.ManagementSession;
import java.util.Locale;
import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Exercises {@code UsbSmartCardConnection} against a third-party USB smart card reader rather than
 * a directly attached YubiKey.
 *
 * <h2>Hardware setup</h2>
 *
 * <ol>
 *   <li>Connect the reader to the Android device over USB OTG. The phone is then the USB host, so
 *       drive the run over wireless adb.
 *   <li>Place a YubiKey 5 NFC on the reader's contactless field (or insert one into a contact
 *       reader). It stays there for the whole run.
 *   <li>Run the {@code ExternalReaderTests} suite.
 * </ol>
 *
 * <p>If a run dies mid-exchange the reader can be left with a halted bulk endpoint, after which
 * every subsequent write times out with {@code Failed to send 10 bytes}. Android exposes no way to
 * clear an endpoint halt, so unplug and replug the reader before retrying.
 *
 * <h2>What this covers</h2>
 *
 * <p>Readers in the HID OMNIKEY 5022-CL class split a long response APDU across several {@code
 * RDR_to_PC_DataBlock} frames and signal continuation via {@code bChainParameter} (CCID 1.10
 * §6.2.1). {@link #testApduSizesOverExternalReader} round-trips payloads up to 2048 bytes and
 * asserts the echo is byte-identical, so a reader that chains fails this test if the host
 * reassembles the chunks wrongly - or drops any of them.
 *
 * <p>The same payloads exercise the opposite direction. A reader advertises how large a CCID
 * message it accepts in {@code dwMaxCCIDMessageLength}, and the host has to split a command APDU
 * that exceeds it across several {@code PC_to_RDR_XfrBlock} messages (CCID 1.10 §6.1.4). The
 * OMNIKEY 5022 advertises 520 bytes, which caps a single frame at 510 APDU bytes, so the 512- and
 * 2048-byte cases both chain outbound. A host that skips the split does not get an error - the
 * reader silently drops the overflow and the card echoes stale bytes under SW {@code 9000} - which
 * is why this test compares the echo byte for byte rather than only checking its length.
 *
 * <h2>Which reader to use</h2>
 *
 * <p>The HID OMNIKEY 5022-CL is the known-good rig, and the one these tests were written against.
 * It advertises {@code dwFeatures = 0x000404BA} (APDU level, short and extended) and {@code
 * dwMaxCCIDMessageLength = 520}, which caps one frame at 510 APDU bytes - small enough that the
 * 512- and 2048-byte payloads below are forced to chain in both directions.
 *
 * <p>That is not left to chance: {@link #testApduSizesOverExternalReader} checks the reader's USB
 * ids before sending anything, so any other reader fails the run with that reason instead of
 * reporting green. The check matters because outbound chaining would otherwise be untested here -
 * with the split in place the echo comes back byte-exact, and with the split skipped the reader
 * silently drops the overflow and the card echoes stale bytes under SW {@code 9000}. Only a reader
 * whose buffer cannot swallow the whole APDU distinguishes the two. Another reader with a small
 * enough buffer works just as well; see {@code assertChainingIsForced} for how to qualify one.
 *
 * <p>Inbound chaining stays the reader's decision - one that advertises a large enough buffer
 * answers in a single frame - so it cannot be forced the same way. To confirm that path ran, enable
 * TRACE logging and look for outbound {@code PC_to_RDR_XfrBlock} frames with an empty data field
 * and {@code wLevelParameter = 0x0010} (on the wire: {@code 6f 00 00 00 00 00 <bSeq> 00 10 00}).
 *
 * <p>Note that the byte-exact framing itself is covered without hardware by {@code
 * UsbSmartCardConnectionTest}, which asserts every frame of both chaining directions against a
 * mocked connection and runs in CI. This suite proves the separate claim that a real reader accepts
 * that framing.
 *
 * <h2>Why it is manual</h2>
 *
 * <p>Both tests are {@link AlwaysManualTest}, so {@link com.yubico.yubikit.FastDeviceTests}
 * excludes them. The suite is also kept out of {@link com.yubico.yubikit.DeviceTests} - it needs
 * hardware that no other suite needs, and it fails rather than skips if a YubiKey is attached
 * directly, so it cannot quietly report success against the ordinary USB path.
 *
 * <p>There is nothing for the automated device suites to pick up here even in principle: a directly
 * attached YubiKey advertises {@code dwMaxCCIDMessageLength = 3072}, capping a frame at 3062 bytes
 * - exactly {@code MaxApduSize.YK4_3}, the ceiling the extended APDU formatter throws past. The
 * protocol layer rejects an oversized APDU before the transport would ever need to split one, so
 * the chaining path is unreachable on that hardware.
 */
public class ExternalCcidReaderTests extends YkInstrumentedTests {

  private static final Logger logger = LoggerFactory.getLogger(ExternalCcidReaderTests.class);

  private static final int[] PAYLOAD_SIZES = {10, 255, 256, 512, 2048};

  /**
   * USB ids of the HID OMNIKEY 5022-CL, the reader this suite was written against and the only one
   * measured to force outbound command chaining. It advertises {@code dwMaxCCIDMessageLength = 520}
   * (so 510 APDU bytes per frame), well under the 2055-byte APDU the largest entry in {@code
   * PAYLOAD_SIZES} produces.
   */
  private static final int OMNIKEY_5022_VENDOR_ID = 0x076b;

  private static final int OMNIKEY_5022_PRODUCT_ID = 0x5022;

  /** Reports which reader answered and what ATR the card in its field returned. */
  @Test
  @Category(AlwaysManualTest.class)
  public void testReaderIdentity() throws Throwable {
    UsbDevice reader = requireExternalReader();
    logger.info(
        "Reader: {} (vid=0x{}, pid=0x{})",
        reader.getProductName(),
        String.format(Locale.ROOT, "%04x", reader.getVendorId()),
        String.format(Locale.ROOT, "%04x", reader.getProductId()));

    try (SmartCardConnection connection =
        requireNonNullDevice().openConnection(SmartCardConnection.class)) {
      byte[] atr = connection.getAtr();
      logger.info("ATR: {}", StringUtils.bytesToHex(atr, 0, atr.length));
      assertTrue("Reader returned an empty ATR; is a card in the field?", atr.length > 0);
    }
  }

  /**
   * Echoes payloads of up to 2048 bytes off the Management applet and asserts each response matches
   * the payload byte for byte. Mirrors {@link
   * com.yubico.yubikit.core.SmartCardProtocolDeviceTests#testApduSizes}, which runs the same
   * exchange over direct USB.
   *
   * <p>It cannot reuse that body as-is because it goes through {@code DeviceUtil.readInfo()}, which
   * keys off the USB product id. Over a reader that id describes the reader, not the card in its
   * field, and {@code readInfo} rejects both {@code UsbPid.OTHER} and a null pid on a USB
   * transport. The firmware version is read off the card instead.
   */
  @Test
  @Category(AlwaysManualTest.class)
  public void testApduSizesOverExternalReader() throws Throwable {
    assertChainingIsForced(requireExternalReader());
    YubiKeyDevice reader = requireNonNullDevice();

    Version version;
    try (ManagementSession management =
        new ManagementSession(reader.openConnection(SmartCardConnection.class))) {
      version = management.getVersion();
    }
    logger.info("Card firmware version: {}", version);

    for (ApduFormat apduFormat : ApduFormat.values()) {
      for (int payloadSize : PAYLOAD_SIZES) {
        SmartCardConnection connection = reader.openConnection(SmartCardConnection.class);
        try (SmartCardProtocol protocol = new SmartCardProtocol(connection)) {
          protocol.configure(
              version,
              new SmartCardProtocol.Configuration.Builder()
                  .setForceShortApdus(ApduFormat.SHORT == apduFormat)
                  .build());
          protocol.select(AppId.MANAGEMENT);

          byte[] payload = RandomUtils.getRandomBytes(payloadSize);
          byte[] response = protocol.sendAndReceive(new Apdu(0, 1, 0, 0, payload));
          assertArrayEquals(
              "Echo mismatch for " + apduFormat + " APDU with " + payloadSize + "-byte payload",
              payload,
              response);
        }
      }
    }
  }

  /**
   * Fails unless the reader is one measured to force outbound command chaining, so that the
   * byte-exact echo in {@link #testApduSizesOverExternalReader} is evidence the chaining path ran.
   * A reader whose {@code dwMaxCCIDMessageLength} is large enough to hold the whole 2055-byte APDU
   * answers it in one frame, and the run reports green while never entering the chaining loop.
   *
   * <p>Whether that is the case is not readable from the public API - the SDK splits internally and
   * exposes no accessor for the advertised limit - so the check is on the reader's USB ids instead.
   * To qualify another reader, run {@link #testReaderIdentity} with logging at DEBUG and read
   * {@code dwMaxCCIDMessageLength} off the "CCID descriptor:" line. If it is under 2065 (2055 APDU
   * bytes plus the 10-byte CCID header) the reader forces chaining, and its ids belong here.
   */
  private void assertChainingIsForced(UsbDevice reader) {
    assertTrue(
        "This reader is not known to force CCID command chaining, so a pass would not prove the "
            + "split ran. Use the HID OMNIKEY 5022-CL, or qualify this one and add its ids - see "
            + "the javadoc on this method. Got vid=0x"
            + String.format(Locale.ROOT, "%04x", reader.getVendorId())
            + ", pid=0x"
            + String.format(Locale.ROOT, "%04x", reader.getProductId()),
        reader.getVendorId() == OMNIKEY_5022_VENDOR_ID
            && reader.getProductId() == OMNIKEY_5022_PRODUCT_ID);
  }

  private YubiKeyDevice requireNonNullDevice() {
    YubiKeyDevice currentDevice = device;
    assertTrue("No device", currentDevice != null);
    return currentDevice;
  }

  /**
   * Fails - deliberately, rather than skipping - unless the session came from a non-Yubico USB
   * device. A directly attached YubiKey would run these tests over the ordinary USB path and report
   * green without having tested a reader at all.
   */
  private UsbDevice requireExternalReader() {
    YubiKeyDevice currentDevice = requireNonNullDevice();
    assertTrue(
        "This suite needs a USB smart card reader, but the session came over "
            + currentDevice.getTransport()
            + ". Connect the reader over USB OTG.",
        currentDevice instanceof UsbYubiKeyDevice);

    UsbDevice usbDevice = ((UsbYubiKeyDevice) currentDevice).getUsbDevice();
    assertNotEquals(
        "A YubiKey is attached directly over USB. Put it on the contactless reader instead - "
            + "otherwise this suite just repeats SmartCardProtocolTests.",
        YubiKeyDevice.YUBICO_VENDOR_ID,
        usbDevice.getVendorId());
    return usbDevice;
  }
}

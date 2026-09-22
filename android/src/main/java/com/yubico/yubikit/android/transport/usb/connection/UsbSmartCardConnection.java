/*
 * Copyright (C) 2019-2026 Yubico.
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

import android.hardware.usb.UsbDeviceConnection;
import android.hardware.usb.UsbEndpoint;
import android.hardware.usb.UsbInterface;
import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.util.StringUtils;
import com.yubico.yubikit.core.util.ZeroingByteArrayOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Locale;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * USB service for interacting with the YubiKey
 *
 * @see <a
 *     href="https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf">https://www.usb.org/sites/default/files/DWG_Smart-Card_CCID_Rev110.pdf</a>
 */
public class UsbSmartCardConnection extends UsbYubiKeyConnection implements SmartCardConnection {

  private static final int TIMEOUT = 1000;

  /**
   * Command Pipe, Bulk-OUT Messages
   *
   * <table>
   * <tr><th>Message Name</th><th>type</th></tr>
   * <tr><td>PC_to_RDR_IccPowerOn</td><td>62h</td></tr>
   * <tr><td>PC_to_RDR_IccPowerOff</td><td>63h</td></tr>
   * <tr><td>PC_to_RDR_GetSlotStatus</td><td>65h</td></tr>
   * <tr><td>PC_to_RDR_XfrBlock</td><td>6Fh</td></tr>
   * <tr><td>PC_to_RDR_GetParameters</td><td>6Ch</td></tr>
   * <tr><td>PC_to_RDR_ResetParameters</td><td>6Dh</td></tr>
   * <tr><td>PC_to_RDR_SetParameters</td><td>61h</td></tr>
   * <tr><td>PC_to_RDR_Escape</td><td>6Bh</td></tr>
   * <tr><td>PC_to_RDR_IccClock</td><td>6Eh</td></tr>
   * <tr><td>PC_to_RDR_T0APDU</td><td>6Ah</td></tr>
   * <tr><td>PC_to_RDR_Secure</td><td>69h</td></tr>
   * <tr><td>PC_to_RDR_Mechanical</td><td>71h</td></tr>
   * <tr><td>PC_to_RDR_Abort</td><td>72h</td></tr>
   * <tr><td>PC_to_RDR_SetDataRateAndClockFrequency</td><td>73h</td></tr>
   * </table>
   */
  private static final byte POWER_ON_MESSAGE_TYPE = (byte) 0x62;

  private static final byte REQUEST_MESSAGE_TYPE = (byte) 0x6f;
  private static final byte RESPONSE_DATA_BLOCK = (byte) 0x80;

  private static final byte STATUS_TIME_EXTENSION = (byte) 0x80;

  // CCID 1.10 §6.1.4 PC_to_RDR_XfrBlock wLevelParameter values. Used
  // to request the next chunk of a response APDU when the reader has
  // split it across multiple CCID frames (see bChainParameter below).
  private static final short LEVEL_PARAMETER_SHORT_APDU = (short) 0x0000;
  private static final short LEVEL_PARAMETER_GET_NEXT_RESPONSE_CHUNK = (short) 0x0010;

  // The same field also chains a command APDU that is larger than the
  // reader's dwMaxCCIDMessageLength across several XfrBlock messages.
  private static final short LEVEL_PARAMETER_COMMAND_FIRST = (short) 0x0001;
  private static final short LEVEL_PARAMETER_COMMAND_LAST = (short) 0x0002;
  private static final short LEVEL_PARAMETER_COMMAND_MIDDLE = (short) 0x0003;

  // CCID 1.10 §6.2.1 RDR_to_PC_DataBlock bChainParameter values. Many
  // contactless CCID readers (e.g. HID OMNIKEY 5022-CL) return long
  // response APDUs in pieces and signal continuation here; the host
  // then has to fetch each subsequent chunk via PC_to_RDR_XfrBlock
  // with wLevelParameter = 0x0010 until bChainParameter == 0x00 or
  // 0x02.
  private static final byte CHAIN_PARAMETER_RESPONSE_COMPLETE = (byte) 0x00;
  private static final byte CHAIN_PARAMETER_RESPONSE_FIRST = (byte) 0x01;
  private static final byte CHAIN_PARAMETER_RESPONSE_LAST = (byte) 0x02;
  private static final byte CHAIN_PARAMETER_RESPONSE_MIDDLE = (byte) 0x03;

  // The reader acknowledges every non-final chunk of a chained command
  // APDU with an empty abData and this value, meaning "continuation of
  // the command APDU is expected". Note it is deliberately outside the
  // 0x00-0x03 range above, so responseIsChained() reports false for an
  // acknowledgement and the two chaining loops cannot interfere.
  private static final byte CHAIN_PARAMETER_COMMAND_CONTINUE = (byte) 0x10;

  // Upper bound on a reassembled chained response: the largest response
  // APDU ISO 7816-4 can express is 65536 data bytes plus SW1SW2. The
  // reader decides how many chunks to send, so without this bound a
  // reader that never signals "last" would grow the buffer until the
  // process runs out of memory.
  private static final int MAX_CHAINED_RESPONSE_LENGTH = 65536 + 2;

  // CCID 1.10 §5.1 requires dwMaxCCIDMessageLength to be at least the
  // 10-byte header plus a 261-byte short APDU. A reader advertising less
  // than that is out of spec, and chunking by a bogus (or zero) value
  // would divide by nothing or emit a frame per byte, so we ignore it
  // and send one frame as before.
  private static final int MIN_MAX_CCID_MESSAGE_LENGTH = 10 + 261;

  // bDescriptorType of the CCID class-specific descriptor (CCID 1.10
  // §5.1). Class-specific descriptor types are numbered per class, so
  // this 0x21 is unrelated to FidoConnectionHandler.HID_DESCRIPTOR_TYPE
  // despite the shared value - only bytes claimed by a CCID interface
  // may be read with the offsets below.
  private static final int CCID_DESCRIPTOR_TYPE = 0x21;

  // bLength of that descriptor: 0x36. Treated as a minimum rather than
  // an equality so a reader that appends vendor fields still parses,
  // and so the fixed offsets read below are known to be present.
  private static final int CCID_DESCRIPTOR_MIN_LENGTH = 54;

  // Offsets into the CCID class descriptor of the two fields this
  // class acts on, both little-endian uint32 (CCID 1.10 §5.1).
  private static final int OFFSET_DW_FEATURES = 40;
  private static final int OFFSET_DW_MAX_CCID_MESSAGE_LENGTH = 44;

  // dwFeatures exchange-level bits (CCID 1.10 §5.1 table 5.1-1).
  private static final int FEATURE_EXCHANGE_TPDU = 0x00010000; // bit 16
  private static final int FEATURE_EXCHANGE_APDU_SHORT = 0x00020000; // bit 17
  private static final int FEATURE_EXCHANGE_APDU_EXTENDED = 0x00040000; // bit 18

  private final UsbDeviceConnection connection;
  private final UsbEndpoint endpointOut, endpointIn;
  private final byte[] atr;

  // dwMaxCCIDMessageLength from the CCID Class Descriptor: the largest
  // CCID message, 10-byte header included, that the reader will accept.
  // 0 when no descriptor was found, in which case we assume any APDU
  // fits - which is what this class did unconditionally before.
  private long maxCcidMessageLength = 0;

  private byte sequence = 0;

  // bChainParameter of the most recent RDR_to_PC_DataBlock returned
  // by transceive(), so sendAndReceive() can drive the chaining loop
  // without having to re-parse the response header.
  private byte lastResponseChainParameter = CHAIN_PARAMETER_RESPONSE_COMPLETE;

  private static final Logger logger = LoggerFactory.getLogger(UsbSmartCardConnection.class);

  /**
   * Sets endpoints and connection and sends power on command if ATR is invalid then throws
   * YubikeyCommunicationException
   *
   * @param connection open usb connection
   * @param ccidInterface ccid interface that was claimed
   * @param endpointIn channel for sending data over USB.
   * @param endpointOut channel for receiving data over USB.
   */
  UsbSmartCardConnection(
      UsbDeviceConnection connection,
      UsbInterface ccidInterface,
      UsbEndpoint endpointIn,
      UsbEndpoint endpointOut)
      throws IOException {
    super(connection, ccidInterface);

    this.connection = connection;
    this.endpointIn = endpointIn;
    this.endpointOut = endpointOut;
    parseCcidClassDescriptor();
    // PC_to_RDR_IccPowerOn command makes the slot "active" if it was "inactive"
    atr = transceive(POWER_ON_MESSAGE_TYPE, new byte[0], LEVEL_PARAMETER_SHORT_APDU);
  }

  /**
   * Read the reader's CCID Class Descriptor (CCID 1.10 §5.1) for the two properties this class acts
   * on: the exchange level it offers, and the largest CCID message it accepts.
   *
   * <p>A reader that only offers the TPDU exchange level expects the host to do T=1 block framing
   * itself, which this class does not implement, so such a reader is rejected here rather than
   * being sent APDU-level {@code XfrBlock}s it will not understand.
   *
   * <p>A descriptor that cannot be found is not an error: the fields keep their defaults and the
   * connection behaves as it did before the descriptor was read at all.
   */
  private void parseCcidClassDescriptor() throws IOException {
    byte[] raw = connection.getRawDescriptors();
    if (raw == null) {
      logger.debug("CCID descriptor: getRawDescriptors() returned null");
      return;
    }
    ByteBuffer descriptors = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);
    // Walk the descriptor list (USB 2.0 §9.5): each entry is bLength,
    // bDescriptorType, plus bLength-2 type-specific bytes.
    int i = 0;
    while (i + 1 < raw.length) {
      int bLength = raw[i] & 0xFF;
      int bDescriptorType = raw[i + 1] & 0xFF;
      if (bLength == 0 || i + bLength > raw.length) break;
      if (bDescriptorType == CCID_DESCRIPTOR_TYPE && bLength >= CCID_DESCRIPTOR_MIN_LENGTH) {
        int dwFeatures = descriptors.getInt(i + OFFSET_DW_FEATURES);
        String exchangeLevel;
        boolean apduLevel =
            (dwFeatures & (FEATURE_EXCHANGE_APDU_SHORT | FEATURE_EXCHANGE_APDU_EXTENDED)) != 0;
        if ((dwFeatures & FEATURE_EXCHANGE_APDU_EXTENDED) != 0) {
          exchangeLevel = "APDU (short+extended)";
        } else if ((dwFeatures & FEATURE_EXCHANGE_APDU_SHORT) != 0) {
          exchangeLevel = "APDU (short only)";
        } else if ((dwFeatures & FEATURE_EXCHANGE_TPDU) != 0) {
          exchangeLevel = "TPDU (host frames T=0/T=1)";
        } else {
          exchangeLevel = "character-level (raw)";
        }
        // The bLength check above guarantees both fields are present.
        this.maxCcidMessageLength =
            descriptors.getInt(i + OFFSET_DW_MAX_CCID_MESSAGE_LENGTH) & 0xFFFFFFFFL;
        logger.debug(
            "CCID descriptor: dwFeatures=0x{} exchangeLevel={} dwMaxCCIDMessageLength={}",
            String.format(Locale.ROOT, "%08X", dwFeatures),
            exchangeLevel,
            maxCcidMessageLength);
        // A reader that advertises both TPDU and APDU accepts either,
        // and APDU-level passthrough is what this class speaks. Only
        // reject when APDU level is not on offer at all.
        if (!apduLevel) {
          throw new IOException(
              "Reader does not support APDU-level exchange (dwFeatures=0x"
                  + String.format(Locale.ROOT, "%08X", dwFeatures)
                  + ", exchange level: "
                  + exchangeLevel
                  + ")");
        }
        return;
      }
      i += bLength;
    }
    logger.debug("CCID descriptor: class-specific descriptor (0x21) not found");
  }

  @Override
  public Transport getTransport() {
    return Transport.USB;
  }

  /**
   * This connection generally supports Extended length APDUs. This can be limited by firmware
   * version of connected YubiKey.
   */
  @Override
  public boolean isExtendedLengthApduSupported() {
    return true;
  }

  @Override
  public byte[] sendAndReceive(byte[] apdu) throws IOException {
    // Send the command APDU, splitting it across several CCID frames if
    // it is larger than the reader will accept. For the common case -
    // an APDU that fits, answered in one frame - this is a single
    // transceive and the whole exchange.
    byte[] response = sendCommand(apdu);
    if (!responseIsChained()) {
      return response;
    }

    // If the reader split the response across multiple CCID frames it
    // signals so via bChainParameter (CCID 1.10 §6.2.1). Pull each
    // subsequent chunk via an empty XfrBlock with
    // wLevelParameter = 0x0010 until the reader reports either a
    // complete (0x00) or last (0x02) chunk.
    try (ZeroingByteArrayOutputStream stream = new ZeroingByteArrayOutputStream()) {
      stream.write(response, 0, response.length);
      while (responseIsChained()) {
        byte[] next =
            transceive(REQUEST_MESSAGE_TYPE, new byte[0], LEVEL_PARAMETER_GET_NEXT_RESPONSE_CHUNK);
        // A chunk that says "more follows" but carries no data makes no
        // progress, so accepting it would loop forever.
        if (next.length == 0) {
          throw new IOException("Empty continuation chunk in chained response");
        }
        if (stream.size() + next.length > MAX_CHAINED_RESPONSE_LENGTH) {
          throw new IOException(
              "Chained response exceeds " + MAX_CHAINED_RESPONSE_LENGTH + " bytes");
        }
        stream.write(next, 0, next.length);
      }
      return stream.toByteArray();
    }
  }

  /**
   * Send a command APDU and return the reader's reply to its final frame.
   *
   * <p>A reader advertises the largest CCID message it accepts in {@code dwMaxCCIDMessageLength}.
   * An APDU that does not fit has to be split across several {@code PC_to_RDR_XfrBlock} messages
   * chained via {@code wLevelParameter} (CCID 1.10 §6.1.4): {@code 0x0001} for the first chunk,
   * {@code 0x0003} for each middle one and {@code 0x0002} for the last. Only the reply to the last
   * chunk carries the response APDU.
   *
   * <p>Skipping the split is not a loud failure. The HID OMNIKEY 5022-CL, which advertises 520
   * bytes, keeps the whole USB packets that fit and silently drops the overflow, so the card sees
   * an APDU whose {@code Lc} overstates the data present and answers with stale buffer contents
   * under SW {@code 9000}.
   */
  private byte[] sendCommand(byte[] apdu) throws IOException {
    int maxPayload = maxCommandPayloadPerFrame();
    if (maxPayload <= 0 || apdu.length <= maxPayload) {
      return transceive(REQUEST_MESSAGE_TYPE, apdu, LEVEL_PARAMETER_SHORT_APDU);
    }

    byte[] reply = new byte[0];
    int offset = 0;
    while (offset < apdu.length) {
      int chunkLength = Math.min(maxPayload, apdu.length - offset);
      boolean isLast = offset + chunkLength == apdu.length;
      short levelParameter;
      if (offset == 0) {
        levelParameter = LEVEL_PARAMETER_COMMAND_FIRST;
      } else if (isLast) {
        levelParameter = LEVEL_PARAMETER_COMMAND_LAST;
      } else {
        levelParameter = LEVEL_PARAMETER_COMMAND_MIDDLE;
      }

      reply =
          transceive(
              REQUEST_MESSAGE_TYPE,
              Arrays.copyOfRange(apdu, offset, offset + chunkLength),
              levelParameter);
      offset += chunkLength;

      // Every chunk but the last must be acknowledged with "continuation
      // expected". Anything else means the reader believes the command is
      // complete, so the bytes we have not sent yet would be lost.
      if (!isLast && lastResponseChainParameter != CHAIN_PARAMETER_COMMAND_CONTINUE) {
        throw new IOException(
            "Reader did not acknowledge chained command chunk: bChainParameter=0x"
                + String.format(Locale.ROOT, "%02X", lastResponseChainParameter));
      }
    }
    return reply;
  }

  /**
   * Bytes of a command APDU that fit in one CCID message, or 0 when the reader did not advertise a
   * usable {@code dwMaxCCIDMessageLength} and we have to assume any APDU fits — the behaviour of
   * this class before chaining existed.
   */
  private int maxCommandPayloadPerFrame() {
    if (maxCcidMessageLength < MIN_MAX_CCID_MESSAGE_LENGTH) {
      return 0;
    }
    return (int)
        Math.min(maxCcidMessageLength - MessageHeader.SIZE_OF_CCID_PREFIX, Integer.MAX_VALUE);
  }

  /** True while the reader has announced further chunks of the current response APDU. */
  private boolean responseIsChained() {
    return lastResponseChainParameter == CHAIN_PARAMETER_RESPONSE_FIRST
        || lastResponseChainParameter == CHAIN_PARAMETER_RESPONSE_MIDDLE;
  }

  @Override
  public byte[] getAtr() {
    return atr.clone();
  }

  /**
   * Does the data exchange between phone and connected usb device with bulk messages All bulk
   * messages begin with a 10-bytes header, followed by message-specific data.
   *
   * @param type the message type identifies the message
   *     <table>
   * <tr><th>Message Name</th><th>type</th></tr>
   * <tr><td>PC_to_RDR_IccPowerOn</td><td>62h</td></tr>
   * <tr><td>PC_to_RDR_IccPowerOff</td><td>63h</td></tr>
   * <tr><td>PC_to_RDR_GetSlotStatus</td><td>65h</td></tr>
   * <tr><td>PC_to_RDR_XfrBlock</td><td>6Fh</td></tr>
   * <tr><td>PC_to_RDR_GetParameters</td><td>6Ch</td></tr>
   * <tr><td>PC_to_RDR_ResetParameters</td><td>6Dh</td></tr>
   * <tr><td>PC_to_RDR_SetParameters</td><td>61h</td></tr>
   * <tr><td>PC_to_RDR_Escape</td><td>6Bh</td></tr>
   * <tr><td>PC_to_RDR_IccClock</td><td>6Eh</td></tr>
   * <tr><td>PC_to_RDR_T0APDU</td><td>6Ah</td></tr>
   * <tr><td>PC_to_RDR_Secure</td><td>69h</td></tr>
   * <tr><td>PC_to_RDR_Mechanical</td><td>71h</td></tr>
   * <tr><td>PC_to_RDR_Abort</td><td>72h</td></tr>
   * <tr><td>PC_to_RDR_SetDataRateAndClockFrequency</td><td>73h</td></tr>
   * </table>
   *
   * @param data message-specific data that needs to be sent to usb device
   * @return received message-specific data from usb device
   * @throws IOException in case if there is communication error occurs or received data is invalid
   */
  private byte[] transceive(byte type, byte[] data, short wLevelParameter) throws IOException {
    // 1. prepare data for sending
    MessageHeader prefix = new MessageHeader(type, data.length, sequence++, wLevelParameter);
    ByteBuffer byteBuffer =
        ByteBuffer.allocate(prefix.size() + data.length)
            .order(ByteOrder.LITTLE_ENDIAN)
            .put(prefix.array())
            .put(data);

    // 2. sent data to device
    byte[] bufferOut = byteBuffer.array();
    int bytesSent = 0;
    int bytesSentPackage = 0;
    while (bytesSent < bufferOut.length || bytesSentPackage == endpointOut.getMaxPacketSize()) {
      bytesSentPackage =
          connection.bulkTransfer(
              endpointOut, bufferOut, bytesSent, bufferOut.length - bytesSent, TIMEOUT);
      if (bytesSentPackage > 0) {
        if (logger.isTraceEnabled()) {
          logger.trace(
              "{} bytes sent over ccid: {}",
              bytesSentPackage,
              StringUtils.bytesToHex(bufferOut, bytesSent, bytesSentPackage));
        }
        bytesSent += bytesSentPackage;
      } else if (bytesSentPackage < 0) {
        throw new IOException("Failed to send " + (bufferOut.length - bytesSent) + " bytes");
      } else {
        // 0 is still considered as success in bulkTransfer description
        // Scenario: if last package size was equal to endpointOut.getMaxPacketSize()
        // we are sending empty package after that to notify end of bulk transfer
        break;
      }
    }

    // 3. read data from device until we receive non-full packet/blob
    ByteArrayOutputStream stream = new ByteArrayOutputStream();
    int bytesRead;
    MessageHeader messageHeader = null;

    boolean receivedExpectedPrefix = false;
    byte[] bufferRead = new byte[endpointIn.getMaxPacketSize()];
    boolean responseRequiresTimeExtension = false;
    do {
      bytesRead = connection.bulkTransfer(endpointIn, bufferRead, bufferRead.length, TIMEOUT);
      if (bytesRead > 0) {
        if (logger.isTraceEnabled()) {
          logger.trace(
              "{} bytes received: {}", bytesRead, StringUtils.bytesToHex(bufferRead, 0, bytesRead));
        }

        if (receivedExpectedPrefix) {
          stream.write(bufferRead, 0, bytesRead);
        } else {
          // 4. parse received data and make sure it's proper format
          messageHeader = new MessageHeader(bufferRead);
          responseRequiresTimeExtension =
              (messageHeader.status & STATUS_TIME_EXTENSION) == STATUS_TIME_EXTENSION;
          if (messageHeader.verify((byte) (sequence - 1))) {
            // if we received expected prefix we can save the rest of received data without
            // verification
            receivedExpectedPrefix = true;
            stream.write(bufferRead, 0, bytesRead);
          } else if (messageHeader.error != 0 && !responseRequiresTimeExtension) {
            logger.debug(
                "Invalid response from card reader bStatus={} and bError={}",
                String.format(Locale.ROOT, "0x%02X", messageHeader.status),
                String.format(Locale.ROOT, "0x%02X", messageHeader.error));
            throw new IOException("Invalid response from card reader");
          }
        }
      } else if (bytesRead < 0) {
        throw new IOException("Failed to read response");
      }
    } while ((bytesRead > 0 && bytesRead == bufferRead.length) || responseRequiresTimeExtension);

    // 5. prepare data for returning to user
    byte[] output = stream.toByteArray();
    if (messageHeader == null || output.length < messageHeader.size()) {
      throw new IOException("Response is invalid");
    }
    // Stash the chain parameter so sendAndReceive() knows whether to
    // pull additional response chunks. For non-RDR_to_PC_DataBlock
    // responses (e.g. the ATR from PowerOn) byte 9 is RFU and we
    // leave the field at COMPLETE so the caller's loop, if any,
    // terminates immediately.
    if (messageHeader.type == RESPONSE_DATA_BLOCK) {
      lastResponseChainParameter = messageHeader.chainParameter;
    } else {
      lastResponseChainParameter = CHAIN_PARAMETER_RESPONSE_COMPLETE;
    }
    int dataLength = Math.min(output.length - messageHeader.size(), messageHeader.dataLength);
    return Arrays.copyOfRange(output, messageHeader.size(), messageHeader.size() + dataLength);
  }

  /**
   * Class parses 10-bytes header of CCID message
   *
   * <p>The header consists of a message type (1 byte), a dataLength field (four bytes), the slot
   * number (1 byte), a sequence number field (1 byte), and either three message specific bytes, or
   * a status field (1 byte), an error field and one message specific byte. The purpose of the
   * 10-byte header is to provide a constant offset at which message data begins across all
   * messages.
   */
  private static class MessageHeader {
    private static final int SIZE_OF_CCID_PREFIX = 10;
    private static final byte SLOT_NUMBER = 0;

    private byte type;
    private int dataLength;
    private byte slot;
    private byte sequence;
    private byte status;
    private byte error;

    // For RDR_to_PC_DataBlock responses this is bChainParameter
    // (CCID 1.10 §6.2.1); for PC_to_RDR_XfrBlock commands the same
    // slot in the outbound header is wLevelParameter (LE short, §6.1.4).
    private byte chainParameter;

    // wLevelParameter to write into outbound XfrBlock headers
    // (§6.1.4). Ignored on inbound parses.
    private short wLevelParameter;

    private MessageHeader(byte[] buffer) {
      if (buffer.length > SIZE_OF_CCID_PREFIX) {
        ByteBuffer responseBuffer =
            ByteBuffer.wrap(buffer, 0, SIZE_OF_CCID_PREFIX).order(ByteOrder.LITTLE_ENDIAN);
        type = responseBuffer.get();
        dataLength = responseBuffer.getInt();
        slot = responseBuffer.get();
        sequence = responseBuffer.get();
        status = responseBuffer.get();
        error = responseBuffer.get();
        chainParameter = responseBuffer.get();
      }
    }

    private MessageHeader(byte type, int length, byte sequence, short wLevelParameter) {
      this.type = type;
      this.dataLength = length;
      this.slot = SLOT_NUMBER;
      this.sequence = sequence;
      this.wLevelParameter = wLevelParameter;
    }

    private byte[] array() {
      // Bytes 7-9 of an outbound XfrBlock are bBWI (always 0 = use
      // default block waiting time) followed by wLevelParameter as a
      // little-endian short.
      ByteBuffer byteBuffer =
          ByteBuffer.allocate(SIZE_OF_CCID_PREFIX)
              .order(ByteOrder.LITTLE_ENDIAN)
              .put(type)
              .putInt(dataLength)
              .put(slot)
              .put(sequence)
              .put((byte) 0)
              .putShort(wLevelParameter);
      return byteBuffer.array();
    }

    private int size() {
      return SIZE_OF_CCID_PREFIX;
    }

    /**
     * The response (Bulk-IN message) always contains the exact same slot number, and sequence
     * number fields from the header that was contained in the Bulk-OUT command message.
     *
     * @param sequence Bulk-OUT message sequence
     * @return true if prefix has expected format
     */
    private boolean verify(byte sequence) {
      if (this.type != RESPONSE_DATA_BLOCK) {
        return false;
      }
      if (this.slot != SLOT_NUMBER) {
        return false;
      }
      if (this.sequence != sequence) {
        return false;
      }

      // Note: according to documentation ignore error if status is 0
      return this.status == 0;
    }
  }
}

/*
 * Copyright (C) 2019-2025 Yubico.
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

package com.yubico.yubikit.core.smartcard;

import com.yubico.yubikit.core.Transport;
import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.scp.DataEncryptor;
import com.yubico.yubikit.core.smartcard.scp.Scp03KeyParams;
import com.yubico.yubikit.core.smartcard.scp.Scp11KeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpState;
import com.yubico.yubikit.core.util.Pair;
import java.io.Closeable;
import java.io.IOException;
import javax.annotation.Nullable;

/**
 * Support class for communication over a SmartCardConnection.
 *
 * <p>This class handles APDU encoding and chaining, and implements workarounds for known issues.
 */
public class SmartCardProtocol implements Closeable {
  private static final byte INS_SELECT = (byte) 0xa4;
  private static final byte P1_SELECT = (byte) 0x04;
  private static final byte P2_SELECT = (byte) 0x00;

  private static final byte INS_SEND_REMAINING = (byte) 0xc0;

  private final byte insSendRemaining;

  private final SmartCardConnection connection;

  private boolean extendedApdus = false;

  private int maxApduSize = MaxApduSize.NEO;

  private ApduProcessor processor;

  public static class Configuration {

    public static final Configuration DEFAULT = new Builder().setForceShortApdus(false).build();

    final boolean forceShortApdus;

    private Configuration(Builder builder) {
      this.forceShortApdus = builder.forceShortApdus;
    }

    public static class Builder {
      private boolean forceShortApdus = false;

      public Builder setForceShortApdus(boolean forceShortApdus) {
        this.forceShortApdus = forceShortApdus;
        return this;
      }

      public Configuration build() {
        return new Configuration(this);
      }
    }
  }

  /**
   * Create new instance of {@link SmartCardProtocol} and selects the application for use
   *
   * @param connection connection to the YubiKey
   */
  public SmartCardProtocol(SmartCardConnection connection) {
    this(connection, INS_SEND_REMAINING);
  }

  public SmartCardProtocol(SmartCardConnection connection, byte insSendRemaining) {
    this.connection = connection;
    this.insSendRemaining = insSendRemaining;
    processor = buildBaseProcessor().first;
  }

  private Pair<ApduProcessor, ApduFormatter> buildBaseProcessor() {
    ApduProcessor result;
    ApduFormatter formatter;
    if (extendedApdus) {
      formatter = new ExtendedApduFormatter(maxApduSize);
      result = new ApduFormatProcessor(connection, formatter);
    } else {
      formatter = new ShortApduFormatter();
      // Short APDUs need command chaining
      result = new CommandChainingProcessor(connection, formatter);
    }

    // Always wrap with response chaining
    result = new ChainedResponseProcessor(result, insSendRemaining);

    return new Pair<>(result, formatter);
  }

  private void reconfigureProcessor() {
    Pair<ApduProcessor, ApduFormatter> pair = buildBaseProcessor();
    ApduProcessor newProcessor = pair.first;

    if (processor instanceof ScpProcessor) {
      // Keep existing SCP state
      newProcessor = new ScpProcessor(newProcessor, pair.second, ((ScpProcessor) processor).state);
    }

    processor = newProcessor;
  }

  @Override
  public void close() throws IOException {
    connection.close();
  }

  /**
   * Enable all relevant settings and workarounds given the firmware version of the YubiKey. Uses a
   * default configuration.
   *
   * @param firmwareVersion the firmware version to use to configure relevant settings
   */
  public void configure(Version firmwareVersion) throws IOException {
    configure(firmwareVersion, Configuration.DEFAULT);
  }

  /**
   * Enable all relevant settings and workarounds given the firmware version of the YubiKey.
   *
   * @param firmwareVersion the firmware version to use to configure relevant settings
   */
  public void configure(Version firmwareVersion, Configuration configuration) throws IOException {
    if (connection.getTransport() == Transport.USB
        && firmwareVersion.isAtLeast(4, 2, 0)
        && firmwareVersion.isLessThan(4, 2, 7)) {
      //noinspection deprecation
      setEnableTouchWorkaround(true);
    } else if (firmwareVersion.isAtLeast(4, 0, 0)) {
      extendedApdus = !configuration.forceShortApdus && connection.isExtendedLengthApduSupported();
      maxApduSize = firmwareVersion.isAtLeast(4, 3, 0) ? MaxApduSize.YK4_3 : MaxApduSize.YK4;
      reconfigureProcessor();
    }
  }

  /**
   * Enable all relevant workarounds given the firmware version of the YubiKey.
   *
   * @param firmwareVersion the firmware version to use for detection to enable the workarounds
   * @deprecated use {@link #configure(Version)} instead.
   */
  @Deprecated
  public void enableWorkarounds(Version firmwareVersion) {
    try {
      configure(firmwareVersion);
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * YubiKey 4.2.0 - 4.2.6 have an issue with the touch timeout being too short in certain cases.
   * Enable this workaround on such devices to trigger sending a dummy command which mitigates the
   * issue.
   *
   * @param enableTouchWorkaround true to enable the workaround, false to disable it
   * @deprecated use {@link #configure(Version)} instead.
   */
  @Deprecated
  public void setEnableTouchWorkaround(boolean enableTouchWorkaround) {
    if (enableTouchWorkaround) {
      extendedApdus = true;
      maxApduSize = MaxApduSize.YK4;
      processor = new TouchWorkaroundProcessor(buildBaseProcessor().first);
    } else {
      reconfigureProcessor();
    }
  }

  /**
   * YubiKey NEO doesn't support extended APDU's for most applications.
   *
   * @param apduFormat the APDU encoding to use when sending commands
   * @deprecated use {@link #configure(Version)} instead.
   */
  @Deprecated
  public void setApduFormat(ApduFormat apduFormat) {
    switch (apduFormat) {
      case SHORT:
        if (extendedApdus) {
          extendedApdus = false;
          reconfigureProcessor();
        }
        break;
      case EXTENDED:
        if (!extendedApdus) {
          extendedApdus = true;
          reconfigureProcessor();
        }
        break;
    }
  }

  /**
   * @return the underlying connection
   */
  public SmartCardConnection getConnection() {
    return connection;
  }

  /**
   * Sends an APDU to SELECT an Application.
   *
   * @param aid the AID to select.
   * @return the response data from selecting the Application
   * @throws IOException in case of connection or communication error
   * @throws ApplicationNotAvailableException in case the AID doesn't match an available application
   */
  public byte[] select(byte[] aid) throws IOException, ApplicationNotAvailableException {
    processor = buildBaseProcessor().first;
    try {
      return sendAndReceive(new Apdu(0, INS_SELECT, P1_SELECT, P2_SELECT, aid));
    } catch (ApduException e) {
      // FUNCTION_NOT_SUPPORTED or FILE_NOT_FOUND mean that it was not possible
      // to select the AID.
      // NEO sometimes returns INVALID_INSTRUCTION instead of these
      if (e.getSw() == SW.FUNCTION_NOT_SUPPORTED
          || e.getSw() == SW.FILE_NOT_FOUND
          || e.getSw() == SW.INVALID_INSTRUCTION) {
        throw new ApplicationNotAvailableException("The application couldn't be selected", e);
      }
      throw new IOException("Unexpected SW", e);
    }
  }

  /**
   * Sends APDU command and receives byte array from connection
   *
   * <p>In case if output has status code that it has remaining info sends another APDU command to
   * receive what's remaining
   *
   * @param command well structured command that needs to be send
   * @return data blob concatenated from all APDU commands that were sent *set of output commands
   *     and send remaining commands)
   * @throws IOException in case of connection and communication error
   * @throws ApduException in case if received error in APDU response
   */
  public byte[] sendAndReceive(Apdu command) throws IOException, ApduException {
    try {
      ApduResponse response = processor.sendApdu(command);
      if (response.getSw() != SW.OK) {
        throw new ApduException(response.getData(), response.getSw());
      }
      return response.getData();
    } catch (BadResponseException e) {
      throw new IOException(e);
    }
  }

  public @Nullable DataEncryptor initScp(ScpKeyParams keyParams)
      throws IOException, ApduException, BadResponseException {
    try {
      ScpState state;
      if (keyParams instanceof Scp03KeyParams) {
        state = initScp03((Scp03KeyParams) keyParams);
      } else if (keyParams instanceof Scp11KeyParams) {
        state = initScp11((Scp11KeyParams) keyParams);
      } else {
        throw new IllegalArgumentException("Unsupported ScpKeyParams");
      }
      return state.getDataEncryptor();
    } catch (ApduException e) {
      if (e.getSw() == SW.CLASS_NOT_SUPPORTED) {
        throw new UnsupportedOperationException("This YubiKey does not support secure messaging");
      }
      throw e;
    }
  }

  private ScpState initScp03(Scp03KeyParams keyParams)
      throws IOException, ApduException, BadResponseException {
    // Start with the base processor
    Pair<ApduProcessor, ApduFormatter> processorPair = buildBaseProcessor();

    // Initialize the SCP state and processor
    Pair<ScpState, byte[]> pair = ScpState.scp03Init(processorPair.first, keyParams, null);
    ScpProcessor scpProcessor =
        new ScpProcessor(processorPair.first, processorPair.second, pair.first);

    // Send EXTERNAL AUTHENTICATE
    // P1 = C-DECRYPTION, R-ENCRYPTION, C-MAC, and R-MAC
    ApduResponse resp = scpProcessor.sendApdu(new Apdu(0x84, 0x82, 0x33, 0, pair.second), false);
    if (resp.getSw() != SW.OK) {
      throw new ApduException(resp.getData(), resp.getSw());
    }

    processor = scpProcessor;
    return pair.first;
  }

  private ScpState initScp11(Scp11KeyParams keyParams)
      throws IOException, ApduException, BadResponseException {
    // Start with the base processor
    Pair<ApduProcessor, ApduFormatter> pair = buildBaseProcessor();

    // Initialize the SCP state and processor
    ScpState scp = ScpState.scp11Init(pair.first, keyParams);

    processor = new ScpProcessor(pair.first, pair.second, scp);
    return scp;
  }
}

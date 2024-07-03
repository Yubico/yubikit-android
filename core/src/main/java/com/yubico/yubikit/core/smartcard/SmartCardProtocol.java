/*
 * Copyright (C) 2019-2022 Yubico.
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
import com.yubico.yubikit.core.smartcard.scp.Scp03KeyParams;
import com.yubico.yubikit.core.smartcard.scp.Scp11KeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpState;
import com.yubico.yubikit.core.util.Pair;

import java.io.Closeable;
import java.io.IOException;

/**
 * Support class for communication over a SmartCardConnection.
 * <p>
 * This class handles APDU encoding and chaining, and implements workarounds for known issues.
 */
public class SmartCardProtocol implements Closeable {
    private static final byte INS_SELECT = (byte) 0xa4;
    private static final byte P1_SELECT = (byte) 0x04;
    private static final byte P2_SELECT = (byte) 0x00;

    private static final byte INS_SEND_REMAINING = (byte) 0xc0;

    private final byte insSendRemaining;

    private final SmartCardConnection connection;

    private ApduFormat apduFormat = ApduFormat.SHORT;

    private int maxApduSize = MaxApduSize.NEO;

    private ApduProcessor processor;

    /**
     * Create new instance of {@link SmartCardProtocol}
     * and selects the application for use
     *
     * @param connection connection to the YubiKey
     */
    public SmartCardProtocol(SmartCardConnection connection) {
        this(connection, INS_SEND_REMAINING);
    }

    public SmartCardProtocol(SmartCardConnection connection, byte insSendRemaining) {
        this.connection = connection;
        this.insSendRemaining = insSendRemaining;
        processor = resetProcessor();
    }

    private ApduProcessor resetProcessor() {
        return new ChainedResponseProcessor(connection, apduFormat == ApduFormat.EXTENDED, maxApduSize, insSendRemaining);
    }

    @Override
    public void close() throws IOException {
        connection.close();
    }

    /**
     * Enable all relevant workarounds given the firmware version of the YubiKey.
     *
     * @param firmwareVersion the firmware version to use for detection to enable the workarounds
     */
    public void enableWorkarounds(Version firmwareVersion) {
        if (connection.getTransport() == Transport.USB
                && firmwareVersion.isAtLeast(4, 2, 0)
                && firmwareVersion.isLessThan(4, 2, 7)) {
            //noinspection deprecation
            setEnableTouchWorkaround(true);
        } else if (firmwareVersion.isAtLeast(4, 0, 0) && !(processor instanceof ScpProcessor)) {
            apduFormat = ApduFormat.EXTENDED;
            maxApduSize = firmwareVersion.isAtLeast(4, 3, 0) ? MaxApduSize.YK4_3 : MaxApduSize.YK4;
            processor = resetProcessor();
        }
    }

    /**
     * YubiKey 4.2.0 - 4.2.6 have an issue with the touch timeout being too short in certain cases. Enable this workaround
     * on such devices to trigger sending a dummy command which mitigates the issue.
     *
     * @param enableTouchWorkaround true to enable the workaround, false to disable it
     * @deprecated use {@link #enableWorkarounds} instead.
     */
    @Deprecated
    public void setEnableTouchWorkaround(boolean enableTouchWorkaround) {
        if (enableTouchWorkaround) {
            apduFormat = ApduFormat.EXTENDED;
            maxApduSize = MaxApduSize.YK4;
            processor = new TouchWorkaroundProcessor(connection, insSendRemaining);
        } else {
            processor = resetProcessor();
        }
    }

    /**
     * YubiKey NEO doesn't support extended APDU's for most applications.
     *
     * @param apduFormat the APDU encoding to use when sending commands
     */
    public void setApduFormat(ApduFormat apduFormat) {
        if (this.apduFormat == apduFormat) {
            return;
        }
        if (apduFormat != ApduFormat.EXTENDED) {
            throw new UnsupportedOperationException("Cannot change from EXTENDED to SHORT APDU format");
        }
        this.apduFormat = apduFormat;
        processor = resetProcessor();
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
     * @throws IOException                      in case of connection or communication error
     * @throws ApplicationNotAvailableException in case the AID doesn't match an available application
     */
    public byte[] select(byte[] aid) throws IOException, ApplicationNotAvailableException {
        processor = resetProcessor();
        try {
            return sendAndReceive(new Apdu(0, INS_SELECT, P1_SELECT, P2_SELECT, aid));
        } catch (ApduException e) {
            // NEO sometimes returns INVALID_INSTRUCTION instead of FILE_NOT_FOUND
            if (e.getSw() == SW.FILE_NOT_FOUND || e.getSw() == SW.INVALID_INSTRUCTION) {
                throw new ApplicationNotAvailableException("The application couldn't be selected", e);
            }
            throw new IOException("Unexpected SW", e);
        }
    }

    /**
     * Sends APDU command and receives byte array from connection
     * In case if output has status code that it has remaining info sends another APDU command to receive what's remaining
     *
     * @param command well structured command that needs to be send
     * @return data blob concatenated from all APDU commands that were sent *set of output commands and send remaining commands)
     * @throws IOException   in case of connection and communication error
     * @throws ApduException in case if received error in APDU response
     */
    public byte[] sendAndReceive(Apdu command) throws IOException, ApduException {
        try {
            ApduResponse response = processor.sendApdu(command);
            if (response.getSw() != SW.OK) {
                throw new ApduException(response.getSw());
            }
            return response.getData();
        } catch (BadResponseException e) {
            throw new IOException(e);
        }
    }

    public void initScp(ScpKeyParams keyParams) throws IOException, ApduException, BadResponseException {
        try {
            if (keyParams instanceof Scp03KeyParams) {
                initScp03((Scp03KeyParams) keyParams);
            } else if (keyParams instanceof Scp11KeyParams) {
                initScp11((Scp11KeyParams) keyParams);
            } else {
                throw new IllegalArgumentException("Unsupported ScpKeyParams");
            }
            apduFormat = ApduFormat.EXTENDED;
            maxApduSize = MaxApduSize.YK4_3;
        } catch (ApduException e) {
            if (e.getSw() == SW.CLASS_NOT_SUPPORTED) {
                throw new UnsupportedOperationException("This YubiKey does not support secure messaging");
            }
            throw e;
        }
    }

    private void initScp03(Scp03KeyParams keyParams) throws IOException, ApduException, BadResponseException {
        Pair<ScpState, byte[]> pair = ScpState.scp03Init(processor, keyParams, null);
        ScpProcessor processor = new ScpProcessor(connection, pair.first, MaxApduSize.YK4_3, insSendRemaining);

        // Send EXTERNAL AUTHENTICATE
        // P1 = C-DECRYPTION, R-ENCRYPTION, C-MAC, and R-MAC
        ApduResponse resp = processor.sendApdu(new Apdu(0x84, 0x82, 0x33, 0, pair.second), false);
        if (resp.getSw() != SW.OK) {
            throw new ApduException(resp.getSw());
        }
        this.processor = processor;
    }

    private void initScp11(Scp11KeyParams keyParams) throws IOException, ApduException, BadResponseException {
        ScpState scp = ScpState.scp11Init(processor, keyParams);
        processor = new ScpProcessor(connection, scp, MaxApduSize.YK4_3, insSendRemaining);
    }
}

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

package com.yubico.yubikit.fido.ctap;

import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.application.ApplicationNotAvailableException;
import com.yubico.yubikit.core.application.ApplicationSession;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import java.io.IOException;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Abstract base class for CTAP sessions.
 *
 * <p>Provides factory methods to create CTAP sessions from YubiKey connections, automatically
 * detecting the supported CTAP version.
 */
public abstract class CtapSession extends ApplicationSession<CtapSession> {

  private static final Logger logger = LoggerFactory.getLogger(CtapSession.class);

  /**
   * Creates a CTAP session from a YubiKey connection.
   *
   * <p>This method attempts to create a CTAP2 session first, and if that fails, falls back to
   * CTAP1. The method tries both FidoConnection and SmartCardConnection types in order.
   *
   * <p>Priority order:
   *
   * <ol>
   *   <li>CTAP2 over FidoConnection (if connection is FidoConnection)
   *   <li>CTAP2 over SmartCardConnection (if connection is SmartCardConnection)
   *   <li>CTAP1 over FidoConnection (if connection is FidoConnection)
   *   <li>CTAP1 over SmartCardConnection (if connection is SmartCardConnection)
   * </ol>
   *
   * @param connection The YubiKey connection (FidoConnection or SmartCardConnection)
   * @return A CtapSession instance (either Ctap2Session or Ctap1Session)
   * @throws IOException if communication with the device fails
   * @throws IllegalArgumentException if the connection type is not supported
   */
  public static @Nullable CtapSession create(YubiKeyConnection connection)
      throws IOException, ApplicationNotAvailableException, IllegalArgumentException {
    return create(connection, null);
  }

  /**
   * Creates a CTAP session from a YubiKey connection with SCP key parameters.
   *
   * <p>This method is similar to {@link #create(YubiKeyConnection)} but allows specifying SCP
   * (Secure Channel Protocol) key parameters for SmartCardConnection. If the connection is a
   * FidoConnection, the scpKeyParams parameter is ignored.
   *
   * @param connection The YubiKey connection (FidoConnection or SmartCardConnection)
   * @param scpKeyParams Optional SCP key parameters (only used for SmartCardConnection)
   * @return A CtapSession instance (either Ctap2Session or Ctap1Session)
   * @throws IOException if communication with the device fails
   * @throws IllegalArgumentException if the connection type is not supported
   */
  public static @Nullable CtapSession create(
      YubiKeyConnection connection, @Nullable ScpKeyParams scpKeyParams)
      throws IOException, ApplicationNotAvailableException, IllegalArgumentException {
    CtapSession ctap2Session = Ctap2Session.create(connection, scpKeyParams);
    if (ctap2Session != null) {
      return ctap2Session;
    }

    return Ctap1Session.create(connection);
  }
}

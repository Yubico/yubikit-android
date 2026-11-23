/*
 * Copyright (C) 2025-2026 Yubico.
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

package com.yubico.yubikit.fido.client;

import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.fido.FidoConnection;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.fido.client.extensions.Extension;
import com.yubico.yubikit.fido.ctap.Ctap1Session;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Utils {

  private static final Logger logger = LoggerFactory.getLogger(Utils.class);

  private Utils() {}

  /**
   * Return SHA-256 hash of the provided input
   *
   * @param message The hash input
   * @return SHA-256 of the input
   */
  public static byte[] hash(byte[] message) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(message);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }

  static WebAuthnClient createWebAuthnClient(
      YubiKeyDevice device, @Nullable List<Extension> extensions)
      throws IOException, CommandException {
    try {
      return createWebAuthnClient(device.openConnection(FidoConnection.class), extensions, null);
    } catch (Exception e) {
      return createWebAuthnClient(
          device.openConnection(SmartCardConnection.class), extensions, null);
    }
  }

  static WebAuthnClient createWebAuthnClient(
      YubiKeyConnection connection,
      @Nullable List<Extension> extensions,
      @Nullable ScpKeyParams scpKeyParams)
      throws IOException, CommandException {
    if (connection instanceof FidoConnection && scpKeyParams != null) {
      throw new IllegalArgumentException("ScpKeyParams provided for FidoConnection");
    }
    try {
      return new Ctap2Client(createCtap2Session(connection, scpKeyParams), extensions);
    } catch (Exception e) {
      return new Ctap1Client(createCtap1Session(connection, scpKeyParams));
    }
  }

  static Ctap2Session createCtap2Session(
      YubiKeyConnection connection, @Nullable ScpKeyParams scpKeyParams)
      throws IOException, CommandException, IllegalArgumentException {
    if (connection instanceof FidoConnection) {
      logger.debug("Attempting to create Ctap2Session from FidoConnection");
      return new Ctap2Session((FidoConnection) connection);
    } else if (connection instanceof SmartCardConnection) {
      logger.debug("Attempting to create Ctap2Session from SmartCardConnection with SCP params");
      return new Ctap2Session((SmartCardConnection) connection, scpKeyParams);
    } else {
      throw new IllegalArgumentException(
          "Unsupported connection type: "
              + connection.getClass().getName()
              + ". Expected FidoConnection or SmartCardConnection.");
    }
  }

  static Ctap1Session createCtap1Session(
      YubiKeyConnection connection, @Nullable ScpKeyParams scpKeyParams)
      throws IOException, CommandException, IllegalArgumentException {
    if (connection instanceof FidoConnection) {
      logger.debug("Attempting to create Ctap1Session from FidoConnection");
      return new Ctap1Session((FidoConnection) connection);
    } else if (connection instanceof SmartCardConnection) {
      logger.debug("Attempting to create Ctap1Session from SmartCardConnection");
      return new Ctap1Session((SmartCardConnection) connection, scpKeyParams);
    } else {
      throw new IllegalArgumentException(
          "Unsupported connection type: "
              + connection.getClass().getName()
              + ". Expected FidoConnection or SmartCardConnection.");
    }
  }

  /**
   * Builds a user entity from a {@code user} map returned by the authenticator, either in an
   * authenticatorGetAssertion response or by credential management enumeration.
   *
   * <p>CTAP 2.1 only guarantees {@code id} here: authenticators omit {@code name} and {@code
   * displayName} when they were empty at registration or are not stored at all (some authenticators
   * never return {@code displayName}). Missing values are therefore not an error; {@code name}
   * defaults to the empty string and {@code displayName} falls back to {@code name}, so callers
   * always have something to show in an account picker or credential list.
   *
   * <p>Do not use this for RP-supplied user entities (e.g. in creation options), where {@code name}
   * and {@code displayName} are mandatory; use {@link PublicKeyCredentialUserEntity#fromMap}.
   */
  static PublicKeyCredentialUserEntity userEntityFromCtap(Map<String, ?> user) {
    byte[] id =
        Objects.requireNonNull(
            (byte[]) user.get(PublicKeyCredentialUserEntity.ID),
            "user.id missing in authenticator response");
    Object nameValue = user.get(PublicKeyCredentialUserEntity.NAME);
    String name = nameValue instanceof String ? (String) nameValue : "";
    Object displayNameValue = user.get(PublicKeyCredentialUserEntity.DISPLAY_NAME);
    String displayName =
        displayNameValue instanceof String && !((String) displayNameValue).isEmpty()
            ? (String) displayNameValue
            : name;
    return new PublicKeyCredentialUserEntity(name, id, displayName);
  }
}

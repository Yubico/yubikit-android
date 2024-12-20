/*
 * Copyright (C) 2023-2024 Yubico.
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

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.internal.Logger;
import com.yubico.yubikit.core.util.Pair;
import com.yubico.yubikit.fido.Cbor;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.slf4j.LoggerFactory;

/**
 * Implements Config commands.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#authenticatorConfig">authenticatorConfig</a>
 */
@SuppressWarnings("unused")
public class Config {
  private static final byte CMD_ENABLE_ENTERPRISE_ATT = 0x01;
  private static final byte CMD_TOGGLE_ALWAYS_UV = 0x02;
  private static final byte CMD_SET_MIN_PIN_LENGTH = 0x03;
  private static final byte CMD_VENDOR_PROTOTYPE = (byte) 0xFF;

  private static final byte PARAM_NEW_MIN_PIN_LENGTH = 0x01;
  private static final byte PARAM_MIN_PIN_LENGTH_RPIDS = 0x02;
  private static final byte PARAM_FORCE_CHANGE_PIN = 0x03;

  private static final byte PARAM_VENDOR_CMD_ID = 0x01;

  private final Ctap2Session ctap;
  @Nullable private final Pair<PinUvAuthProtocol, byte[]> pinUv;

  private static final org.slf4j.Logger logger = LoggerFactory.getLogger(Config.class);

  /**
   * Construct a new Config object using a specified PIN/UV Auth protocol and token.
   *
   * @param ctap an active CTAP2 connection
   * @param pinUvAuth the PIN/UV Auth protocol to use
   * @param pinUvToken the PIN/UV token to use
   */
  public Config(
      Ctap2Session ctap, @Nullable PinUvAuthProtocol pinUvAuth, @Nullable byte[] pinUvToken) {

    if (!isSupported(ctap.getCachedInfo())) {
      throw new IllegalStateException("Not supported");
    }

    this.ctap = ctap;
    if (pinUvAuth != null && pinUvToken != null) {
      this.pinUv = new Pair<>(pinUvAuth, pinUvToken);
    } else {
      this.pinUv = null;
    }
  }

  public static boolean isSupported(Ctap2Session.InfoData infoData) {
    return Boolean.TRUE.equals(infoData.getOptions().get("authnrCfg"));
  }

  public static boolean supportsVendorPrototypeConfigCommands(Ctap2Session.InfoData infoData) {
    return infoData.getVendorPrototypeConfigCommands() != null;
  }

  private Map<Integer, ?> call(byte subCommand, @Nullable Map<?, ?> subCommandParams)
      throws IOException, CommandException {
    Integer pinUvProtocol = null;
    byte[] pinUvAuthParam = null;

    final byte[] header = new byte[32];
    Arrays.fill(header, (byte) 0xff);

    if (pinUv != null) {
      ByteBuffer msg;
      if (subCommandParams != null) {
        final byte[] enc = Cbor.encode(subCommandParams);
        msg =
            ByteBuffer.allocate(34 + enc.length)
                .put(header)
                .put((byte) 0x0d)
                .put(subCommand)
                .put(enc);
      } else {
        msg = ByteBuffer.allocate(34).put(header).put((byte) 0x0d).put(subCommand);
      }

      pinUvProtocol = pinUv.first.getVersion();
      pinUvAuthParam = pinUv.first.authenticate(pinUv.second, msg.array());
    }

    return ctap.config(subCommand, subCommandParams, pinUvProtocol, pinUvAuthParam);
  }

  /**
   * Enables Enterprise Attestation. If already enabled, this command is ignored.
   *
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#enable-enterprise-attestation">Enable
   *     Enterprise Attestation</a>
   */
  public void enableEnterpriseAttestation() throws IOException, CommandException {
    Logger.debug(logger, "Enabling enterprise attestation");
    call(CMD_ENABLE_ENTERPRISE_ATT, null);
    Logger.info(logger, "Enterprise attestation enabled");
  }

  /**
   * Toggle the alwaysUV setting. When true, the Authenticator always requires UV for credential
   * assertion.
   *
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#toggle-alwaysUv">Toggle
   *     Always Require User Verification</a>
   */
  public void toggleAlwaysUv() throws IOException, CommandException {
    Logger.debug(logger, "Toggling always UV");
    call(CMD_TOGGLE_ALWAYS_UV, null);
    Logger.info(logger, "Always UV toggled");
  }

  /**
   * Set the minimum PIN length allowed when setting/changing the PIN. When true, the Authenticator
   * always requires UV for credential assertion.
   *
   * @param minPinLength The minimum PIN length the Authenticator should allow.
   * @param rpIds A list of RP IDs which should be allowed to get the current minimum PIN length.
   * @param forceChangePin True if the Authenticator should enforce changing the PIN before the next
   *     use.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#setMinPINLength">Setting
   *     a minimum PIN Length</a>
   */
  public void setMinPinLength(
      @Nullable Integer minPinLength,
      @Nullable List<String> rpIds,
      @Nullable Boolean forceChangePin)
      throws IOException, CommandException {
    Logger.debug(logger, "Setting minimum PIN length");
    Map<Byte, Object> parameters = new HashMap<>();
    if (minPinLength != null) parameters.put(PARAM_NEW_MIN_PIN_LENGTH, minPinLength);
    if (rpIds != null) parameters.put(PARAM_MIN_PIN_LENGTH_RPIDS, rpIds);
    if (forceChangePin != null) parameters.put(PARAM_FORCE_CHANGE_PIN, forceChangePin);

    call(CMD_SET_MIN_PIN_LENGTH, parameters.isEmpty() ? null : parameters);

    if (minPinLength != null) Logger.info(logger, "Minimum PIN length set");
    if (rpIds != null) Logger.info(logger, "Minimum PIN length RP ID list set");
    if (forceChangePin != null) Logger.info(logger, "ForcePINChange set");
  }

  /**
   * Allows vendors to test authenticator configuration features.
   *
   * @param vendorCommandId Vendor-assigned command ID.
   * @throws IOException A communication error in the transport layer.
   * @throws CommandException A communication in the protocol layer.
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#vendorPrototype">Vendor
   *     Prototype Command</a>
   */
  public Map<Integer, ?> vendorPrototype(Integer vendorCommandId)
      throws IOException, CommandException {
    Logger.debug(logger, "Call vendor prototype command");
    final Map<Integer, ?> response =
        call(CMD_VENDOR_PROTOTYPE, Collections.singletonMap(PARAM_VENDOR_CMD_ID, vendorCommandId));
    Logger.info(logger, "Vendor prototype command executed");
    return response;
  }
}

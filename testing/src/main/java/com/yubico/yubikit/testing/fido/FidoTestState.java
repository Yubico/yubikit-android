/*
 * Copyright (C) 2024-2025 Yubico.
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

package com.yubico.yubikit.testing.fido;

import static com.yubico.yubikit.testing.fido.utils.ConfigHelper.getConfig;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.UsbPid;
import com.yubico.yubikit.core.YubiKeyConnection;
import com.yubico.yubikit.core.YubiKeyDevice;
import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.fido.client.BasicWebAuthnClient;
import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.client.CredentialManager;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Config;
import com.yubico.yubikit.fido.ctap.CredentialManagement;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity;
import com.yubico.yubikit.management.Capability;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.support.DeviceUtil;
import com.yubico.yubikit.testing.TestState;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

public class FidoTestState extends TestState {

  private final PinUvAuthProtocol pinUvAuthProtocol;
  private final boolean isFipsApproved;
  public final boolean alwaysUv;

  public static class Builder extends TestState.Builder<Builder> {

    private final PinUvAuthProtocol pinUvAuthProtocol;
    private boolean setPin = false;

    public Builder(
        YubiKeyDevice device,
        List<Class<? extends YubiKeyConnection>> supportedConnectionTypes,
        UsbPid usbPid,
        PinUvAuthProtocol pinUvAuthProtocol) {
      super(device, supportedConnectionTypes, usbPid);
      this.pinUvAuthProtocol = pinUvAuthProtocol;
    }

    @Override
    public Builder getThis() {
      return this;
    }

    public Builder setPin(boolean setPin) {
      this.setPin = setPin;
      return this;
    }

    public FidoTestState build() throws Throwable {
      return new FidoTestState(this);
    }
  }

  private FidoTestState(Builder builder) throws Throwable {
    super(builder);

    this.pinUvAuthProtocol = builder.pinUvAuthProtocol;

    boolean isFidoFipsCapable = false;
    DeviceInfo deviceInfo = null;

    try (YubiKeyConnection connection = openConnection()) {
      try {
        deviceInfo = DeviceUtil.readInfo(connection, null);
        assertNotNull(deviceInfo);
        isFidoFipsCapable =
            (deviceInfo.getFipsCapable() & Capability.FIDO2.bit) == Capability.FIDO2.bit;

        assumeTrue(
            "This YubiKey does not support FIDO2", deviceInfo.getVersion().isAtLeast(5, 0, 0));
      } catch (IllegalArgumentException ignored) {
        // failed to get device info, this is not a YubiKey
      }

      Ctap2Session session = getSession(connection, scpParameters.getKeyParams());
      assumeTrue("CTAP2 not supported", session != null);
      assumeTrue(
          "PIN UV Protocol not supported", supportsPinUvAuthProtocol(session, pinUvAuthProtocol));

      if (isFidoFipsCapable) {
        assumeTrue(
            "Ignoring FIPS tests which don't use PinUvAuthProtocolV2",
            pinUvAuthProtocol.getVersion() == 2);
      }

      if (builder.setPin) {
        verifyOrSetPin(session);
      }

      @Nullable Boolean alwaysUv = (Boolean) session.getInfo().getOptions().get("alwaysUv");
      if (isFidoFipsCapable && Boolean.FALSE.equals(alwaysUv)) {
        // set always UV on
        Config config = getConfig(session, this);
        config.toggleAlwaysUv();
        alwaysUv = true;
      }
      this.alwaysUv = Boolean.TRUE.equals(alwaysUv);

      boolean fipsApproved = false;
      try {
        deviceInfo = DeviceUtil.readInfo(connection, null);
        fipsApproved =
            (deviceInfo.getFipsApproved() & Capability.FIDO2.bit) == Capability.FIDO2.bit;
      } catch (IllegalArgumentException ignored) {
        // not a YubiKey
      }

      this.isFipsApproved = fipsApproved;

      // after changing the PIN and setting alwaysUv, we expect a FIPS capable device
      // to be FIPS approved
      if (builder.setPin && isFidoFipsCapable) {
        assertNotNull(deviceInfo);
        assertTrue("Device not FIDO FIPS approved as expected", this.isFipsApproved);
      }

      // remove existing credentials
      if (builder.setPin) {
        // cannot use CredentialManager if there is no PIN set
        session = getSession(connection, scpParameters.getKeyParams());
        deleteExistingCredentials(session);
      }
    }
  }

  public boolean isFipsApproved() {
    return isFipsApproved;
  }

  public PinUvAuthProtocol getPinUvAuthProtocol() {
    return pinUvAuthProtocol;
  }

  boolean supportsPinUvAuthProtocol(Ctap2Session session, PinUvAuthProtocol pinUvAuthProtocol) {
    final List<Integer> pinUvAuthProtocols = session.getCachedInfo().getPinUvAuthProtocols();
    return pinUvAuthProtocols.contains(pinUvAuthProtocol.getVersion());
  }

  void deleteExistingCredentials(Ctap2Session session)
      throws IOException, CommandException, ClientError {
    final BasicWebAuthnClient webauthn = new BasicWebAuthnClient(session);
    if (!CredentialManagement.isSupported(session.getCachedInfo())) {
      return;
    }
    CredentialManager credentialManager = webauthn.getCredentialManager(TestData.PIN);
    final List<String> rpIds = credentialManager.getRpIdList();
    for (String rpId : rpIds) {
      Map<PublicKeyCredentialDescriptor, PublicKeyCredentialUserEntity> credentials =
          credentialManager.getCredentials(rpId);
      for (PublicKeyCredentialDescriptor credential : credentials.keySet()) {
        credentialManager.deleteCredential(credential);
      }
    }
    assertEquals("Failed to remove all credentials", 0, credentialManager.getCredentialCount());
  }

  /** Attempts to set (or verify) the default PIN, or fails. */
  void verifyOrSetPin(Ctap2Session session) throws IOException, CommandException {

    Ctap2Session.InfoData info = session.getInfo();

    ClientPin pin = new ClientPin(session, pinUvAuthProtocol);
    boolean pinSet = Objects.requireNonNull((Boolean) info.getOptions().get("clientPin"));

    try {
      if (!pinSet) {
        pin.setPin(TestData.PIN);
      } else {
        pin.getPinToken(
            TestData.PIN, ClientPin.PIN_PERMISSION_MC | ClientPin.PIN_PERMISSION_GA, "localhost");
      }
    } catch (CommandException e) {
      fail(
          "YubiKey cannot be used for test, failed to set/verify PIN. Please reset "
              + "and try again.");
    }
  }

  public void withDeviceCallback(StatefulDeviceCallback<FidoTestState> callback) throws Throwable {
    callback.invoke(this);
  }

  public void withCtap2(TestState.StatefulSessionCallback<Ctap2Session, FidoTestState> callback)
      throws Throwable {
    try (YubiKeyConnection connection = openConnection()) {
      final Ctap2Session ctap2 = getSession(connection, scpParameters.getKeyParams());
      assumeTrue("No CTAP2 support", ctap2 != null);
      callback.invoke(ctap2, this);
    }
    reconnect();
  }

  public <R> R withCtap2(SessionCallbackT<Ctap2Session, R> callback) throws Throwable {
    R result;
    try (YubiKeyConnection connection = openConnection()) {
      final Ctap2Session ctap2 = getSession(connection, scpParameters.getKeyParams());
      assumeTrue("No CTAP2 support", ctap2 != null);
      result = callback.invoke(ctap2);
    }
    reconnect();
    return result;
  }

  public void withCtap2(SessionCallback<Ctap2Session> callback) throws Throwable {
    try (YubiKeyConnection connection = openConnection()) {
      final Ctap2Session ctap2 = getSession(connection, scpParameters.getKeyParams());
      assumeTrue("No CTAP2 support", ctap2 != null);
      callback.invoke(ctap2);
    }
    reconnect();
  }
}

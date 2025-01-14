/*
 * Copyright (C) 2020-2024 Yubico.
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

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.core.application.CommandState;
import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.webauthn.SerializationType;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class Ctap2SessionTests {

  public static void testCtap2GetInfo(Ctap2Session session, FidoTestState state) {
    Ctap2Session.InfoData info = session.getCachedInfo();

    List<String> versions = info.getVersions();
    assertTrue(
        "Returned version does not contain any recognized version",
        versions.contains("U2F_V2")
            || versions.contains("FIDO_2_0")
            || versions.contains("FIDO_2_1_PRE")
            || versions.contains("FIDO_2_1"));

    // Check AAGUID
    byte[] aaguid = info.getAaguid();
    assertEquals("AAGUID incorrect length", 16, aaguid.length);

    // Check options
    Map<String, ?> options = info.getOptions();
    assertEquals("Option 'plat' incorrect", false, options.get("plat"));
    assertEquals("Option 'rk' incorrect", true, options.get("rk"));
    assertEquals("Option 'up' incorrect", true, options.get("up"));
    assertTrue("Options do not contain 'clientPIN'", options.containsKey("clientPin"));

    // Check PIN/UV Auth protocol
    List<Integer> pinUvAuthProtocols = info.getPinUvAuthProtocols();
    assertThat(
        "Number of PIN protocols incorrect", pinUvAuthProtocols.size(), greaterThanOrEqualTo(1));

    if (state.isFipsApproved() && !state.isUsbTransport()) {
      // FIPS only supports PIN/UV Auth protocol 2 over NFC
      assertThat("Number of PIN protocols incorrect", pinUvAuthProtocols.size(), equalTo(1));
      assertTrue("PIN protocol incorrect", pinUvAuthProtocols.contains(2));
    } else {
      // we expect at least protocol 1 to be present
      assertThat(
          "Number of PIN protocols incorrect", pinUvAuthProtocols.size(), greaterThanOrEqualTo(1));
      assertTrue("PIN protocol incorrect", pinUvAuthProtocols.contains(1));
    }
  }

  public static void testCancelCborCommandImmediate(Ctap2Session session, FidoTestState state)
      throws Throwable {
    doTestCancelCborCommand(session, state, false);
  }

  public static void testCancelCborCommandAfterDelay(Ctap2Session session, FidoTestState state)
      throws Throwable {
    doTestCancelCborCommand(session, state, true);
  }

  public static void testReset(FidoTestState state) throws Throwable {

    state.withCtap2(
        session -> {
          assumeFalse(
              "Skipping reset test - authenticator supports bio enrollment",
              session.getCachedInfo().getOptions().containsKey("bioEnroll"));

          session.reset(null);

          // Verify that the pin is no longer configured
          Boolean clientPin = (Boolean) session.getInfo().getOptions().get("clientPin");
          boolean pinConfigured = (clientPin != null) && clientPin;
          assertFalse("PIN should not be configured after a reset", pinConfigured);
        });
  }

  private static void doTestCancelCborCommand(
      Ctap2Session session, FidoTestState testState, boolean delay) throws Throwable {

    assumeTrue("Not a USB connection", testState.isUsbTransport());

    ClientPin pin = new ClientPin(session, testState.getPinUvAuthProtocol());
    byte[] pinToken =
        pin.getPinToken(TestData.PIN, ClientPin.PIN_PERMISSION_MC, TestData.RP.getId());
    byte[] pinAuth = pin.getPinUvAuth().authenticate(pinToken, TestData.CLIENT_DATA_HASH);

    CommandState state = new CommandState();
    if (delay) {
      Executors.newSingleThreadScheduledExecutor()
          .schedule(state::cancel, 500, TimeUnit.MILLISECONDS);
    } else {
      state.cancel();
    }

    final SerializationType cborType = SerializationType.CBOR;

    try {
      session.makeCredential(
          TestData.CLIENT_DATA_HASH,
          TestData.RP.toMap(cborType),
          TestData.USER.toMap(cborType),
          Collections.singletonList(TestData.PUB_KEY_CRED_PARAMS_ES256.toMap(cborType)),
          null,
          null,
          null,
          pinAuth,
          pin.getPinUvAuth().getVersion(),
          null,
          state);
      fail("Make credential completed without being cancelled.");
    } catch (CtapException e) {
      assertThat(e.getCtapError(), is(CtapException.ERR_KEEPALIVE_CANCEL));
    }

    session.getInfo(); // Make sure connection still works.
  }
}

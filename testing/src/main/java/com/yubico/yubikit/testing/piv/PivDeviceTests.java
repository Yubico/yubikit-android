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
package com.yubico.yubikit.testing.piv;

import static com.yubico.yubikit.piv.PivSession.FEATURE_AES_KEY;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.SW;
import com.yubico.yubikit.piv.InvalidPinException;
import com.yubico.yubikit.piv.ManagementKeyType;
import com.yubico.yubikit.piv.PivSession;
import java.io.IOException;
import org.bouncycastle.util.encoders.Hex;
import org.hamcrest.CoreMatchers;
import org.hamcrest.MatcherAssert;
import org.junit.Assert;
import org.junit.Assume;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PivDeviceTests {

  private static final Logger logger = LoggerFactory.getLogger(PivDeviceTests.class);

  public static void testManagementKey(PivSession piv, PivTestState state)
      throws BadResponseException, IOException, ApduException {
    byte[] key2 = Hex.decode("010203040102030401020304010203040102030401020304");

    ManagementKeyType managementKeyType = piv.getManagementKeyType();

    logger.debug("Authenticate with the wrong key");
    try {
      piv.authenticate(key2);
      Assert.fail("Authenticated with wrong key");
    } catch (ApduException e) {
      Assert.assertEquals(SW.SECURITY_CONDITION_NOT_SATISFIED, e.getSw());
    }

    logger.debug("Change management key");
    piv.authenticate(state.managementKey);
    piv.setManagementKey(managementKeyType, key2, false);

    logger.debug("Authenticate with the old key");
    try {
      piv.authenticate(state.managementKey);
      Assert.fail("Authenticated with wrong key");
    } catch (ApduException e) {
      Assert.assertEquals(SW.SECURITY_CONDITION_NOT_SATISFIED, e.getSw());
    }

    logger.debug("Change management key");
    piv.authenticate(key2);
    piv.setManagementKey(managementKeyType, state.managementKey, false);
  }

  public static void testManagementKeyType(PivSession piv, PivTestState state)
      throws BadResponseException, IOException, ApduException {
    Assume.assumeTrue("No AES key support", piv.supports(FEATURE_AES_KEY));

    ManagementKeyType managementKeyType = piv.getManagementKeyType();
    byte[] aes128Key = Hex.decode("01020304010203040102030401020304");

    logger.debug("Change management key type");
    piv.authenticate(state.managementKey);
    piv.setManagementKey(ManagementKeyType.AES128, aes128Key, false);
    Assert.assertEquals(ManagementKeyType.AES128, piv.getManagementKeyType());

    try {
      piv.authenticate(state.managementKey);
      Assert.fail("Authenticated with wrong key type");
    } catch (IllegalArgumentException e) {
      // ignored
    }

    // set original management key type
    piv.authenticate(aes128Key);
    piv.setManagementKey(managementKeyType, state.managementKey, false);
  }

  public static void testPin(PivSession piv, PivTestState state)
      throws ApduException, InvalidPinException, IOException, BadResponseException {
    // Ensure we only try this if the default management key is set.
    piv.authenticate(state.managementKey);

    logger.debug("Verify PIN");
    char[] pin2 = "11231123".toCharArray();
    piv.verifyPin(state.pin);
    MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(3));

    logger.debug("Verify with wrong PIN");
    try {
      piv.verifyPin(pin2);
      Assert.fail("Verify with wrong PIN");
    } catch (InvalidPinException e) {
      MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(2));
      MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(2));
    }

    logger.debug("Change PIN with wrong PIN");
    try {
      piv.changePin(pin2, state.pin);
      Assert.fail("Change PIN with wrong PIN");
    } catch (InvalidPinException e) {
      MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(1));
      MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(1));
    }

    logger.debug("Change PIN");
    piv.changePin(state.pin, pin2);
    piv.verifyPin(pin2);

    logger.debug("Verify with wrong PIN");
    try {
      piv.verifyPin(state.pin);
      Assert.fail("Verify with wrong PIN");
    } catch (InvalidPinException e) {
      MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(2));
      MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(2));
    }

    logger.debug("Change PIN");
    piv.changePin(pin2, state.pin);
  }

  public static void testPuk(PivSession piv, PivTestState state)
      throws ApduException, InvalidPinException, IOException, BadResponseException {
    // Ensure we only try this if the default management key is set.
    piv.authenticate(state.managementKey);

    // Change PUK
    char[] puk2 = "12341234".toCharArray();
    piv.changePuk(state.puk, puk2);
    piv.verifyPin(state.pin);

    // Block PIN
    while (piv.getPinAttempts() > 0) {
      try {
        piv.verifyPin(puk2);
      } catch (InvalidPinException e) {
        // Re-run until blocked...
      }
    }

    // Verify PIN blocked
    try {
      piv.verifyPin(state.pin);
    } catch (InvalidPinException e) {
      MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(0));
      MatcherAssert.assertThat(piv.getPinAttempts(), CoreMatchers.equalTo(0));
    }

    // Try unblock with wrong PUK
    try {
      piv.unblockPin(state.puk, state.pin);
      Assert.fail("Unblock with wrong PUK");
    } catch (InvalidPinException e) {
      MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(2));
    }

    // Unblock PIN
    piv.unblockPin(puk2, state.pin);

    // Try to change PUK with wrong PUK
    try {
      piv.changePuk(state.puk, puk2);
      Assert.fail("Change PUK with wrong PUK");
    } catch (InvalidPinException e) {
      MatcherAssert.assertThat(e.getAttemptsRemaining(), CoreMatchers.equalTo(2));
    }

    // Change PUK
    piv.changePuk(puk2, state.puk);
  }
}

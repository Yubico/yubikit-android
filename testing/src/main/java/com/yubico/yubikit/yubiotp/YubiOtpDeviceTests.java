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

package com.yubico.yubikit.yubiotp;

import static com.yubico.yubikit.yubiotp.YubiOtpSession.FEATURE_CHECK_CONFIGURED;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

import com.yubico.yubikit.Codec;
import com.yubico.yubikit.core.application.CommandException;
import java.io.IOException;
import java.util.Arrays;

public class YubiOtpDeviceTests {
  public static void testSlotConfigured(YubiOtpSession session, YubiOtpTestState ignoredState)
      throws IOException, CommandException {

    assumeTrue(
        "Key does not support checking of slot configuration",
        FEATURE_CHECK_CONFIGURED.isSupportedBy(session.getVersion()));

    ConfigurationState configState = session.getConfigurationState();
    assertFalse("Slot.ONE should not be configured", configState.isConfigured(Slot.ONE));
    assertFalse("Slot.TWO should not be configured", configState.isConfigured(Slot.TWO));

    byte[] key1 = new byte[16];
    Arrays.fill(key1, (byte) 'a');
    session.putConfiguration(Slot.ONE, new HmacSha1SlotConfiguration(key1), null, null);

    configState = session.getConfigurationState();
    assertTrue("Slot.ONE should be configured", configState.isConfigured(Slot.ONE));
    assertFalse("Slot.TWO should not be configured", configState.isConfigured(Slot.TWO));

    session.putConfiguration(Slot.TWO, new HmacSha1SlotConfiguration(key1), null, null);

    configState = session.getConfigurationState();
    assertTrue("Slot.ONE should be configured", configState.isConfigured(Slot.ONE));
    assertTrue("Slot.TWO should be configured", configState.isConfigured(Slot.TWO));

    session.deleteConfiguration(Slot.ONE, null);

    configState = session.getConfigurationState();
    assertFalse("Slot.ONE should not be configured", configState.isConfigured(Slot.ONE));
    assertTrue("Slot.TWO should be configured", configState.isConfigured(Slot.TWO));

    assumeTrue(
        "Key does not support slot swapping",
        YubiOtpSession.FEATURE_SWAP.isSupportedBy(session.getVersion()));

    session.swapConfigurations();

    configState = session.getConfigurationState();
    assertTrue("Slot.ONE should be configured after swap", configState.isConfigured(Slot.ONE));
    assertFalse("Slot.TWO should not be configured after swap", configState.isConfigured(Slot.TWO));

    session.deleteConfiguration(Slot.ONE, null);

    configState = session.getConfigurationState();
    assertFalse("Slot.ONE should not be configured", configState.isConfigured(Slot.ONE));
    assertFalse("Slot.TWO should not be configured", configState.isConfigured(Slot.TWO));
  }

  public static void testSlotTouchTriggered(
      YubiOtpSession session, YubiOtpTestState ignoredState, Slot slot)
      throws IOException, CommandException {

    assumeTrue("Version must be 3.0 or later", session.getVersion().isAtLeast(3, 0, 0));
    assumeTrue(
        "Key does not support checking of touch trigger",
        YubiOtpSession.FEATURE_CHECK_TOUCH_TRIGGERED.isSupportedBy(session.getVersion()));

    byte[] key = new byte[16];
    Arrays.fill(key, (byte) 'a');
    session.putConfiguration(slot, new HmacSha1SlotConfiguration(key), null, null);

    ConfigurationState configState = session.getConfigurationState();
    assertTrue("Slot should be configured", configState.isConfigured(slot));
    assertFalse("Slot should not be touch triggered", configState.isTouchTriggered(slot));

    byte[] password = new byte[] {(byte) 'a'};
    session.putConfiguration(slot, new StaticPasswordSlotConfiguration(password), null, null);

    configState = session.getConfigurationState();
    assertTrue("Slot should be configured", configState.isConfigured(slot));
    assertTrue("Slot should be touch triggered", configState.isTouchTriggered(slot));

    session.deleteConfiguration(slot, null);

    configState = session.getConfigurationState();
    assertFalse("Slot should not be configured", configState.isConfigured(slot));
    assertFalse("Slot should not be touch triggered", configState.isTouchTriggered(slot));
  }

  public static void testConfigureNdef(YubiOtpSession session, YubiOtpTestState ignoredState)
      throws IOException, CommandException {

    assumeTrue(
        "Key does not support NDEF",
        YubiOtpSession.FEATURE_NDEF.isSupportedBy(session.getVersion()));

    byte[] password = new byte[] {(byte) 'a'};
    session.putConfiguration(Slot.ONE, new StaticPasswordSlotConfiguration(password), null, null);
    session.setNdefConfiguration(Slot.ONE, null, null);
  }

  public static void testCalculateHmacSha1(YubiOtpSession session, YubiOtpTestState ignoredState)
      throws IOException, CommandException {

    assumeTrue(
        "Key does not support challenge-response",
        YubiOtpSession.FEATURE_CHALLENGE_RESPONSE.isSupportedBy(session.getVersion()));

    byte[] key = Codec.fromHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    byte[] challenge = "Hi There".getBytes();
    byte[] expectedResponse = Codec.fromHex("b617318655057264e28bc0b6fb378c8ef146be00");

    session.putConfiguration(Slot.TWO, new HmacSha1SlotConfiguration(key), null, null);
    byte[] response = session.calculateHmacSha1(Slot.TWO, challenge, null);

    assertArrayEquals("HMAC-SHA1 response should match expected", expectedResponse, response);
  }
}

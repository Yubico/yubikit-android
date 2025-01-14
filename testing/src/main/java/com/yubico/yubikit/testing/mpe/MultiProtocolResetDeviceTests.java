/*
 * Copyright (C) 2024 Yubico.
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
package com.yubico.yubikit.testing.mpe;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.keys.PrivateKeyValues;
import com.yubico.yubikit.fido.ctap.ClientPin;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV2;
import com.yubico.yubikit.piv.KeyType;
import com.yubico.yubikit.piv.PinPolicy;
import com.yubico.yubikit.piv.PivSession;
import com.yubico.yubikit.piv.Slot;
import com.yubico.yubikit.piv.TouchPolicy;
import com.yubico.yubikit.testing.piv.PivTestUtils;
import java.io.IOException;
import java.security.KeyPair;
import java.util.Objects;
import org.bouncycastle.util.encoders.Hex;

public class MultiProtocolResetDeviceTests {

  public static void testSettingPivPinBlocksFidoReset(PivSession piv, MpeTestState state)
      throws Throwable {
    piv.changePin("123456".toCharArray(), "multipin".toCharArray());
    assertFalse(state.isPivResetBlocked());
    assertTrue(state.isFidoResetBlocked());
  }

  public static void testPivOperationBlocksFidoReset(PivSession piv, MpeTestState state)
      throws IOException, CommandException {
    KeyPair rsaKeyPair = PivTestUtils.loadKey(KeyType.RSA1024);
    piv.authenticate(Hex.decode("010203040506070801020304050607080102030405060708"));
    piv.putKey(
        Slot.RETIRED1,
        PrivateKeyValues.fromPrivateKey(rsaKeyPair.getPrivate()),
        PinPolicy.DEFAULT,
        TouchPolicy.DEFAULT);

    assertFalse(state.isPivResetBlocked());
    assertTrue(state.isFidoResetBlocked());
  }

  public static void testSettingFidoPinBlocksPivReset(Ctap2Session ctap2, MpeTestState state)
      throws IOException, CommandException {

    PinUvAuthProtocol pinUvAuthProtocol = new PinUvAuthProtocolV2();
    // note that max PIN length is 8 because it is shared with PIV
    char[] defaultPin = "11234567".toCharArray();

    Ctap2Session.InfoData info = ctap2.getCachedInfo();
    ClientPin pin = new ClientPin(ctap2, pinUvAuthProtocol);
    boolean pinSet = Objects.requireNonNull((Boolean) info.getOptions().get("clientPin"));
    assertFalse(pinSet);
    pin.setPin(defaultPin);

    assertTrue(state.isPivResetBlocked());
    assertFalse(state.isFidoResetBlocked());
  }
}

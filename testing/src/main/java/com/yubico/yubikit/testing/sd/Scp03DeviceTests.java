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

package com.yubico.yubikit.testing.sd;

import static org.junit.Assert.assertThrows;
import static org.junit.Assume.assumeFalse;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.smartcard.ApduException;
import com.yubico.yubikit.core.smartcard.scp.KeyRef;
import com.yubico.yubikit.core.smartcard.scp.Scp03KeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;
import com.yubico.yubikit.core.smartcard.scp.StaticKeys;
import com.yubico.yubikit.core.util.RandomUtils;
import java.io.IOException;

public class Scp03DeviceTests {

  static final KeyRef DEFAULT_KEY = new KeyRef((byte) 0x01, (byte) 0xff);
  static final ScpKeyParams defaultRef =
      new Scp03KeyParams(DEFAULT_KEY, StaticKeys.getDefaultKeys());

  public static void before(SecurityDomainTestState state) throws Throwable {
    assumeFalse(
        "SCP03 not supported over NFC on FIPS capable devices",
        state.getDeviceInfo().getFipsCapable() != 0 && !state.isUsbTransport());
    state.withSecurityDomain(SecurityDomainSession::reset);
  }

  public static void testImportKey(SecurityDomainTestState state) throws Throwable {

    final byte[] sk =
        new byte[] {
          0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
          0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        };
    final StaticKeys staticKeys = new StaticKeys(sk, sk, sk);
    final KeyRef ref = new KeyRef((byte) 0x01, (byte) 0x01);
    final ScpKeyParams params = new Scp03KeyParams(ref, staticKeys);

    assumeFalse(
        "SCP03 not supported over NFC on FIPS capable devices",
        state.getDeviceInfo().getFipsCapable() != 0 && !state.isUsbTransport());

    state.withSecurityDomain(
        session -> {
          session.authenticate(defaultRef);
          session.putKey(ref, staticKeys, 0);
        });

    state.withSecurityDomain(
        session -> {
          session.authenticate(params);
        });

    state.withSecurityDomain(
        session -> {
          // cannot use default key to authenticate
          assertThrows(ApduException.class, () -> session.authenticate(defaultRef));
        });
  }

  public static void testDeleteKey(SecurityDomainTestState state) throws Throwable {
    final StaticKeys staticKeys1 = randomStaticKeys();
    final StaticKeys staticKeys2 = randomStaticKeys();
    final KeyRef keyRef1 = new KeyRef((byte) 0x01, (byte) 0x10);
    final KeyRef keyRef2 = new KeyRef((byte) 0x01, (byte) 0x55);
    final Scp03KeyParams ref1 = new Scp03KeyParams(keyRef1, staticKeys1);
    final ScpKeyParams ref2 = new Scp03KeyParams(keyRef2, staticKeys2);

    state.withSecurityDomain(
        session -> {
          session.authenticate(defaultRef);
          session.putKey(keyRef1, staticKeys1, 0);
        });

    // authenticate with the new key and put the second
    state.withSecurityDomain(
        session -> {
          session.authenticate(ref1);
          session.putKey(keyRef2, staticKeys2, 0);
        });

    state.withSecurityDomain(
        session -> {
          session.authenticate(ref1);
        });

    state.withSecurityDomain(
        session -> {
          session.authenticate(ref2);
        });

    // delete first key
    state.withSecurityDomain(
        session -> {
          session.authenticate(ref2);
          session.deleteKey(keyRef1, false);
        });

    state.withSecurityDomain(
        session -> {
          assertThrows(ApduException.class, () -> session.authenticate(ref1));
        });

    state.withSecurityDomain(
        session -> {
          session.authenticate(ref2);
        });

    // delete the second key
    state.withSecurityDomain(
        session -> {
          session.authenticate(ref2);
          session.deleteKey(keyRef2, true); // the last key
        });

    state.withSecurityDomain(
        session -> {
          assertThrows(ApduException.class, () -> session.authenticate(ref2));
        });
  }

  public static void testReplaceKey(SecurityDomainTestState state) throws Throwable {
    final StaticKeys staticKeys1 = randomStaticKeys();
    final StaticKeys staticKeys2 = randomStaticKeys();

    final KeyRef keyRef1 = new KeyRef((byte) 0x01, (byte) 0x10);
    final KeyRef keyRef2 = new KeyRef((byte) 0x01, (byte) 0x55);

    final ScpKeyParams ref1 = new Scp03KeyParams(keyRef1, staticKeys1);
    final ScpKeyParams ref2 = new Scp03KeyParams(keyRef2, staticKeys2);

    state.withSecurityDomain(
        session -> {
          session.authenticate(defaultRef);
          session.putKey(keyRef1, staticKeys1, 0);
        });

    // authenticate with the new key and replace it with the second
    state.withSecurityDomain(
        session -> {
          session.authenticate(ref1);
          session.putKey(keyRef2, staticKeys2, keyRef1.getKvn());
        });

    state.withSecurityDomain(
        session -> {
          assertThrows(ApduException.class, () -> session.authenticate(ref1));
        });

    state.withSecurityDomain(
        session -> {
          session.authenticate(ref2);
        });
  }

  public static void testWrongKey(SecurityDomainTestState state) throws Throwable {
    final StaticKeys staticKeys = randomStaticKeys();
    final KeyRef ref = new KeyRef((byte) 0x01, (byte) 0x01);
    final ScpKeyParams params = new Scp03KeyParams(ref, staticKeys);

    state.withSecurityDomain(
        session -> {
          assertThrows(ApduException.class, () -> session.authenticate(params));
          assertThrows(ApduException.class, () -> verifyAuth(session));
        });

    state.withSecurityDomain(
        session -> {
          session.authenticate(defaultRef);
        });
  }

  private static StaticKeys randomStaticKeys() {
    return new StaticKeys(
        RandomUtils.getRandomBytes(16),
        RandomUtils.getRandomBytes(16),
        RandomUtils.getRandomBytes(16));
  }

  private static void verifyAuth(SecurityDomainSession session)
      throws BadResponseException, ApduException, IOException {
    KeyRef ref = new KeyRef(ScpKid.SCP11b, (byte) 0x7f);
    session.generateEcKey(ref, 0);
    session.deleteKey(ref, false);
  }
}

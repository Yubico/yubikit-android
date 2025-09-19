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

package com.yubico.yubikit.testing.core;

import static org.junit.Assert.assertArrayEquals;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.smartcard.Apdu;
import com.yubico.yubikit.core.smartcard.ApduFormat;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardConnection;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.core.smartcard.scp.KeyRef;
import com.yubico.yubikit.core.smartcard.scp.Scp03KeyParams;
import com.yubico.yubikit.core.smartcard.scp.Scp11KeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKeyParams;
import com.yubico.yubikit.core.smartcard.scp.ScpKid;
import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;
import com.yubico.yubikit.core.smartcard.scp.StaticKeys;
import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.management.DeviceInfo;
import com.yubico.yubikit.management.VersionQualifier;
import java.security.cert.X509Certificate;
import java.util.List;
import org.junit.Assume;

public class SmartCardProtocolDeviceTests {
  private static final ScpKeyParams defaultKeyParams =
      new Scp03KeyParams(new KeyRef((byte) 0x01, (byte) 0xff), StaticKeys.getDefaultKeys());

  public static void testApduSizesOverScp(CoreTestState state) throws Throwable {
    testApduSizes(state, true);
  }

  public static void testApduSizes(CoreTestState state) throws Throwable {
    testApduSizes(state, false);
  }

  private static void testApduSizes(CoreTestState state, boolean useScp) throws Throwable {
    DeviceInfo deviceInfo = state.getDeviceInfo();
    VersionQualifier versionQualifier = deviceInfo.getVersionQualifier();
    Version version = versionQualifier.getVersion();

    Assume.assumeTrue(
        "This test requires a device with Management session", version.isAtLeast(4, 0, 0));

    if (useScp) {
      Assume.assumeTrue("This test requires a device with SCP support", version.isAtLeast(5, 7, 2));
    }

    final KeyRef keyRef = new KeyRef(ScpKid.SCP11b, (byte) 0x01);

    if (useScp) {
      state.withSecurityDomain(null, SecurityDomainSession::reset);
    }

    ScpKeyParams keyParams =
        useScp
            ? state.withSecurityDomain(
                defaultKeyParams,
                session -> {
                  final List<X509Certificate> bundle = session.getCertificateBundle(keyRef);
                  return new Scp11KeyParams(keyRef, bundle.get(bundle.size() - 1).getPublicKey());
                })
            : null;

    int[] payloadSizes = {10, 255, 256, 512, 2048};

    for (ApduFormat apduFormat : ApduFormat.values()) {
      for (int payloadSize : payloadSizes) {
        state.withDevice(
            device -> {
              SmartCardConnection connection = device.openConnection(SmartCardConnection.class);

              try (SmartCardProtocol protocol = new SmartCardProtocol(connection)) {
                SmartCardProtocol.Configuration configuration =
                    new SmartCardProtocol.Configuration.Builder()
                        .setForceShortApdus(ApduFormat.SHORT == apduFormat)
                        .build();
                protocol.configure(version, configuration);
                protocol.select(AppId.MANAGEMENT);
                if (useScp && keyParams != null) {
                  protocol.initScp(keyParams);
                }

                byte[] payload = RandomUtils.getRandomBytes(payloadSize);
                byte[] response = protocol.sendAndReceive(new Apdu(0, 1, 0, 0, payload));
                assertArrayEquals(payload, response);
              }
            });
      }
    }
  }
}

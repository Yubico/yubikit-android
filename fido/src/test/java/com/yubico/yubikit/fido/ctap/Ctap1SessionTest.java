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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyByte;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.Version;
import com.yubico.yubikit.core.fido.FidoProtocol;
import com.yubico.yubikit.core.smartcard.AppId;
import com.yubico.yubikit.core.smartcard.SmartCardProtocol;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AttestedCredentialData;
import com.yubico.yubikit.fido.webauthn.AuthenticatorData;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import org.junit.Assert;
import org.junit.Test;

public class Ctap1SessionTest {

  @Test
  public void opensOverSmartCard() throws Exception {
    SmartCardProtocol mock = mock(SmartCardProtocol.class);
    when(mock.sendAndReceive(argThat(apdu -> apdu.getIns() == Ctap1Session.INS_VERSION)))
        .thenReturn("U2F_V2".getBytes(StandardCharsets.UTF_8));
    try (Ctap1Session session = new Ctap1Session(mock, null)) {
      Assert.assertEquals(new Version(0, 0, 0), session.getVersion());
      Assert.assertEquals("U2F_V2", session.getU2fVersion());
    }

    verify(mock).select(AppId.FIDO);
    verify(mock).close();
  }

  @Test
  public void opensOverFido() throws Exception {
    FidoProtocol mock = mock(FidoProtocol.class);
    when(mock.getVersion()).thenReturn(new Version(1, 2, 3));
    when(mock.sendAndReceive(anyByte(), any(), any()))
        .thenReturn(
            ByteBuffer.allocate(8)
                .put("U2F_V3".getBytes(StandardCharsets.UTF_8))
                .put((byte) 0x90)
                .put((byte) 0x00)
                .array());
    try (Ctap1Session session = new Ctap1Session(mock)) {
      Assert.assertEquals(new Version(1, 2, 3), session.getVersion());
      Assert.assertEquals("U2F_V3", session.getU2fVersion());
    }

    verify(mock).close();
  }

  /**
   * The authenticator data is assembled into a filled buffer that must be read back from position
   * 0. Getting that wrong throws {@link java.nio.BufferUnderflowException} out of {@code
   * parseFrom}.
   */
  @Test
  public void buildsAttestationFromRegistrationData() {
    byte[] appParam = filled(32, (byte) 0xA1);
    byte[] coordinateX = filled(32, (byte) 0xB2);
    byte[] coordinateY = filled(32, (byte) 0xC3);
    byte[] keyHandle = filled(16, (byte) 0xD4);
    // Minimal DER SEQUENCEs. The parser TLV-decodes the certificate and everything after it, so
    // both have to be well formed, but neither is X.509 or ECDSA parsed here.
    byte[] certificate = new byte[] {0x30, 0x03, 0x02, 0x01, 0x2A};
    byte[] signature = new byte[] {0x30, 0x06, 0x02, 0x01, 0x2B, 0x02, 0x01, 0x2C};

    Ctap1Session.RegistrationData registrationData =
        new Ctap1Session.RegistrationData(
            ByteBuffer.allocate(
                    1 + 65 + 1 + keyHandle.length + certificate.length + signature.length)
                .put(Ctap1Session.RegistrationData.RESERVED_BYTE)
                .put((byte) 0x04)
                .put(coordinateX)
                .put(coordinateY)
                .put((byte) keyHandle.length)
                .put(keyHandle)
                .put(certificate)
                .put(signature)
                .array());

    AttestationObject attestation = registrationData.getAttestation(appParam);

    Assert.assertEquals("fido-u2f", attestation.getFormat());

    AuthenticatorData authenticatorData = attestation.getAuthenticatorData();
    Assert.assertArrayEquals(appParam, authenticatorData.getRpIdHash());
    Assert.assertEquals(0, authenticatorData.getSignCount());
    Assert.assertTrue(authenticatorData.isUp());
    Assert.assertTrue(authenticatorData.isAt());

    AttestedCredentialData credentialData = authenticatorData.getAttestedCredentialData();
    Assert.assertArrayEquals(new byte[16], credentialData.getAaguid());
    Assert.assertArrayEquals(keyHandle, credentialData.getCredentialId());
    Assert.assertArrayEquals(coordinateX, (byte[]) credentialData.getCosePublicKey().get(-2));
    Assert.assertArrayEquals(coordinateY, (byte[]) credentialData.getCosePublicKey().get(-3));

    Assert.assertArrayEquals(signature, (byte[]) attestation.getAttestationStatement().get("sig"));
  }

  private static byte[] filled(int length, byte value) {
    byte[] bytes = new byte[length];
    Arrays.fill(bytes, value);
    return bytes;
  }
}

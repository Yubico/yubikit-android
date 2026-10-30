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

package com.yubico.yubikit.fido.client;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider;
import com.yubico.yubikit.fido.ctap.Ctap1Session;
import com.yubico.yubikit.fido.webauthn.AttestationConveyancePreference;
import com.yubico.yubikit.fido.webauthn.AttestationObject;
import com.yubico.yubikit.fido.webauthn.AuthenticatorAttestationResponse;
import com.yubico.yubikit.fido.webauthn.AuthenticatorData;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialParameters;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRpEntity;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class AttestationConveyanceTest {
  private static final byte[] CREDENTIAL_ID = {9, 8, 7, 6};
  private static final byte[] CERTIFICATE = {0x30, 0x03, 0x01, 0x02, 0x03};

  private static byte[] fixed32(java.math.BigInteger value) {
    byte[] raw = value.toByteArray();
    byte[] out = new byte[32];
    int len = Math.min(raw.length, 32);
    System.arraycopy(raw, raw.length - len, out, 32 - len, len);
    return out;
  }

  private static AttestationObject directAttestation() throws Exception {
    return attestation("fido-u2f", new byte[16], true);
  }

  private static AttestationObject attestation(
      String format, byte[] aaguid, boolean withCertificate) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
    generator.initialize(256);
    ECPublicKey key = (ECPublicKey) generator.generateKeyPair().getPublic();
    Map<Integer, Object> cose = new HashMap<>();
    cose.put(1, 2);
    cose.put(3, -7);
    cose.put(-1, 1);
    cose.put(-2, fixed32(key.getW().getAffineX()));
    cose.put(-3, fixed32(key.getW().getAffineY()));
    ByteArrayOutputStream authData = new ByteArrayOutputStream();
    authData.write(new byte[32]);
    authData.write(0x41);
    authData.write(new byte[4]);
    authData.write(aaguid);
    authData.write(ByteBuffer.allocate(2).putShort((short) CREDENTIAL_ID.length).array());
    authData.write(CREDENTIAL_ID);
    authData.write(Cbor.encode(cose));

    Map<String, Object> attStmt = new HashMap<>();
    attStmt.put("sig", new byte[] {1, 2});
    if (withCertificate) {
      attStmt.put("x5c", Collections.singletonList(CERTIFICATE));
    }
    return new AttestationObject(
        format,
        AuthenticatorData.parseFrom(ByteBuffer.wrap(authData.toByteArray())),
        attStmt,
        null,
        null,
        null);
  }

  private static Map<?, ?> decode(AuthenticatorAttestationResponse response) {
    return (Map<?, ?>) Cbor.decode(response.getAttestationObject());
  }

  private static void assertSuppressed(AttestationObject result, AttestationObject original) {
    assertEquals("none", result.getFormat());
    assertTrue(result.getAttestationStatement().isEmpty());
    assertEquals(original.getAuthenticatorData(), result.getAuthenticatorData());
  }

  @Test
  public void noneAndDefaultSuppressAttestation() throws Exception {
    AttestationObject original = directAttestation();
    assertSuppressed(
        AttestationConveyance.apply(original, AttestationConveyancePreference.NONE), original);
    assertSuppressed(AttestationConveyance.apply(original, null), original);
  }

  /**
   * WebAuthn leaves self attestation untouched for "none": packed format, no certificate and a zero
   * AAGUID. The attestation is returned as it was.
   */
  @Test
  public void selfAttestationIsLeftAlone() throws Exception {
    AttestationObject self = attestation("packed", new byte[16], false);
    assertSame(self, AttestationConveyance.apply(self, AttestationConveyancePreference.NONE));
    assertSame(self, AttestationConveyance.apply(self, null));
  }

  /** Each condition of the self attestation exception has to hold, or the statement is replaced. */
  @Test
  public void almostSelfAttestationIsSuppressed() throws Exception {
    byte[] aaguid = new byte[16];
    aaguid[15] = 1;
    AttestationObject[] notSelf = {
      attestation("packed", new byte[16], true), // has a certificate
      attestation("packed", aaguid, false), // has an AAGUID
      attestation("fido-u2f", new byte[16], false), // not the packed format
    };
    for (AttestationObject original : notSelf) {
      assertSuppressed(AttestationConveyance.apply(original, null), original);
    }
  }

  @Test
  public void requestedConveyanceIsRetained() throws Exception {
    AttestationObject original = directAttestation();
    for (String preference :
        new String[] {
          AttestationConveyancePreference.DIRECT,
          AttestationConveyancePreference.INDIRECT,
          AttestationConveyancePreference.ENTERPRISE
        }) {
      AttestationObject result = AttestationConveyance.apply(original, preference);
      assertEquals("fido-u2f", result.getFormat());
      assertTrue(result.getAttestationStatement().containsKey("x5c"));
    }
  }

  @Test
  public void ctap1MakeCredentialHonorsConveyance() throws Exception {
    AttestationObject direct = directAttestation();
    Ctap1Session session = mock(Ctap1Session.class);
    Ctap1Session.RegistrationData registration = mock(Ctap1Session.RegistrationData.class);
    when(registration.getAttestation(any())).thenReturn(direct);
    when(registration.getKeyHandle()).thenReturn(CREDENTIAL_ID);
    when(session.register(any(), any())).thenReturn(registration);
    Ctap1Client client = new Ctap1Client(session);

    for (String preference :
        new String[] {
          null, AttestationConveyancePreference.NONE, AttestationConveyancePreference.DIRECT
        }) {
      PublicKeyCredentialCreationOptions options = mock(PublicKeyCredentialCreationOptions.class);
      when(options.getRp()).thenReturn(new PublicKeyCredentialRpEntity("Example", "example.com"));
      when(options.getPubKeyCredParams())
          .thenReturn(
              Collections.singletonList(new PublicKeyCredentialParameters("public-key", -7)));
      when(options.getExcludeCredentials()).thenReturn(Collections.emptyList());
      when(options.getAttestation())
          .thenReturn(preference != null ? preference : AttestationConveyancePreference.NONE);
      ClientDataProvider clientData = mock(ClientDataProvider.class);
      when(clientData.getHash()).thenReturn(new byte[32]);
      when(clientData.getClientDataJson()).thenReturn(new byte[] {'{', '}'});

      PublicKeyCredential credential =
          client.makeCredential(clientData, options, "example.com", null, null, null);
      AuthenticatorAttestationResponse response =
          (AuthenticatorAttestationResponse) credential.getResponse();
      Map<?, ?> attestationObject = decode(response);
      boolean expectsDirect = AttestationConveyancePreference.DIRECT.equals(preference);
      assertEquals(expectsDirect ? "fido-u2f" : "none", attestationObject.get("fmt"));
      assertEquals(!expectsDirect, ((Map<?, ?>) attestationObject.get("attStmt")).isEmpty());
      // The credential stays usable
      assertNotNull(response.getPublicKey());
      assertArrayEquals(CREDENTIAL_ID, credential.getRawId());
    }
  }
}

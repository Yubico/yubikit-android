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

package com.yubico.yubikit.fido.client;

import static com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType.PUBLIC_KEY;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.isNotNull;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.fido.CtapException;
import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialDescriptor;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import org.junit.Test;

public class BasicWebAuthnClientUtilsTest {

  static final String RP_EXAMPLE = "example.com";

  @Test
  public void testFilterCredsOnEmptyList() throws Throwable {
    assertNull(
        BasicWebAuthnClient.Utils.filterCreds(
            new CtapMockBuilder().build(),
            RP_EXAMPLE,
            Collections.emptyList(),
            RP_EXAMPLE,
            null,
            null));

    assertNull(
        BasicWebAuthnClient.Utils.filterCreds(
            new CtapMockBuilder().credentialsForRpId(RP_EXAMPLE, credId(16)).build(),
            RP_EXAMPLE,
            Collections.emptyList(),
            RP_EXAMPLE,
            null,
            null));
  }

  @Test
  public void testFilterCredsByRpId() throws Throwable {

    byte[] cred1 = credId("CRED1");
    byte[] cred2 = credId("CRED2");

    List<PublicKeyCredentialDescriptor> descriptors =
        Arrays.asList(
            new PublicKeyCredentialDescriptor(PUBLIC_KEY, cred1),
            new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(16)));

    // cred1 will not be found in test.com and is not present for RP_EXAMPLE
    assertNull(
        BasicWebAuthnClient.Utils.filterCreds(
            new CtapMockBuilder()
                .credentialsForRpId("test.com", credId(16), cred1, credId(16))
                .credentialsForRpId(RP_EXAMPLE, cred2)
                .build(),
            RP_EXAMPLE,
            descriptors,
            RP_EXAMPLE,
            null,
            null));

    // cred1 will be found in test.com
    PublicKeyCredentialDescriptor desc =
        BasicWebAuthnClient.Utils.filterCreds(
            new CtapMockBuilder()
                .credentialsForRpId("test.com", credId(16), cred1, credId(16))
                .credentialsForRpId(RP_EXAMPLE, cred2)
                .build(),
            "test.com",
            descriptors,
            "test.com",
            null,
            null);
    assertNotNull(desc);
    assertArrayEquals(cred1, desc.getId());
  }

  @Test
  public void testFilterCredsPinUvParams() throws Throwable {

    byte[] cred1 = credId("CRED1");

    Ctap2Session ctap =
        new CtapMockBuilder().credentialsForRpId(RP_EXAMPLE, credId(16), cred1, credId(16)).build();

    List<PublicKeyCredentialDescriptor> descriptors =
        Arrays.asList(
            new PublicKeyCredentialDescriptor(PUBLIC_KEY, cred1),
            new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(16)));

    PinUvAuthProtocol mockPinUvAuthProtocol = mock(PinUvAuthProtocol.class);
    doReturn(new byte[32]).when(mockPinUvAuthProtocol).authenticate(any(), any());
    byte[] pinUvAuthToken = new byte[32];

    assertNotNull(
        BasicWebAuthnClient.Utils.filterCreds(
            ctap, RP_EXAMPLE, descriptors, RP_EXAMPLE, mockPinUvAuthProtocol, null));

    // no authenticate is called
    verify(mockPinUvAuthProtocol, never()).authenticate(any(), any());
    // check that null pinUv params are passed to getAssertions
    verify(ctap, atLeastOnce())
        .getAssertions(anyString(), any(), any(), any(), any(), isNull(), isNull(), any());

    assertNotNull(
        BasicWebAuthnClient.Utils.filterCreds(
            ctap, RP_EXAMPLE, descriptors, RP_EXAMPLE, null, pinUvAuthToken));

    // check that null pinUv params are passed to getAssertions
    verify(ctap, atLeastOnce())
        .getAssertions(anyString(), any(), any(), any(), any(), isNull(), isNull(), any());

    assertNotNull(
        BasicWebAuthnClient.Utils.filterCreds(
            ctap, RP_EXAMPLE, descriptors, RP_EXAMPLE, mockPinUvAuthProtocol, pinUvAuthToken));

    // authenticate is called
    verify(mockPinUvAuthProtocol, times(1)).authenticate(any(), any());
    // check that non-null pinUv params are passed to getAssertions
    verify(ctap, atLeastOnce())
        .getAssertions(anyString(), any(), any(), any(), any(), isNotNull(), isNotNull(), any());
  }

  @Test
  public void testFilterCredsOfLongCredentialIds() throws Throwable {
    byte[] longIdCred = credId(256);
    byte[] target = credId(32);

    Ctap2Session ctap =
        new CtapMockBuilder()
            .maxCredentialIdLength(128)
            .credentialsForRpId(
                "rp.com",
                target,
                longIdCred, // longer than max, will be filtered out
                credId(64),
                credId(64))
            .build();

    assertNull(
        BasicWebAuthnClient.Utils.filterCreds(
            ctap,
            null,
            Arrays.asList(
                new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(16)),
                new PublicKeyCredentialDescriptor(PUBLIC_KEY, longIdCred)),
            "rp.com",
            null,
            null));

    PublicKeyCredentialDescriptor cred =
        BasicWebAuthnClient.Utils.filterCreds(
            ctap,
            null,
            Arrays.asList(
                new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(16)),
                new PublicKeyCredentialDescriptor(PUBLIC_KEY, target)),
            "rp.com",
            null,
            null);
    assertNotNull(cred);
    assertArrayEquals(target, cred.getId());
  }

  @Test
  public void testFilterCredsChunking() throws Throwable {
    byte[] target = credId(32);

    CtapMockBuilder ctapBuilder =
        new CtapMockBuilder().maxCredentialIdLength(64).maxCredentialCountInList(8);

    PublicKeyCredentialDescriptor dummy = new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(48));

    List<PublicKeyCredentialDescriptor> descriptors =
        Arrays.asList(
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            // target credential is the last in the last chunk
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            dummy,
            new PublicKeyCredentialDescriptor(PUBLIC_KEY, target));

    PublicKeyCredentialDescriptor cred =
        BasicWebAuthnClient.Utils.filterCreds(
            ctapBuilder.credentialsForRpId(RP_EXAMPLE, credId(64), target).build(),
            null,
            descriptors,
            RP_EXAMPLE,
            null,
            null);
    assertNotNull(cred);
    assertArrayEquals(target, cred.getId());

    cred =
        BasicWebAuthnClient.Utils.filterCreds(
            ctapBuilder.credentialsForRpId(RP_EXAMPLE, target, credId(64)).build(),
            null,
            descriptors,
            RP_EXAMPLE,
            null,
            null);
    assertNotNull(cred);
    assertArrayEquals(target, cred.getId());

    assertNull(
        BasicWebAuthnClient.Utils.filterCreds(
            ctapBuilder.credentialsForRpId(RP_EXAMPLE, credId(64)).build(),
            null,
            descriptors,
            RP_EXAMPLE,
            null,
            null));

    // try smaller chunks
    cred =
        BasicWebAuthnClient.Utils.filterCreds(
            ctapBuilder
                .credentialsForRpId(RP_EXAMPLE, credId(64), target)
                .maxCredentialCountInList(3)
                .build(),
            null,
            descriptors,
            RP_EXAMPLE,
            null,
            null);
    assertNotNull(cred);
    assertArrayEquals(target, cred.getId());
  }

  @Test
  public void testFilterCredsExceptionHandling() throws Throwable {
    try {
      BasicWebAuthnClient.Utils.filterCreds(
          new CtapMockBuilder().throwCtapError(true).build(),
          RP_EXAMPLE,
          Collections.singletonList(new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId("TEST"))),
          RP_EXAMPLE,
          null,
          null);
    } catch (Exception e) {
      assertTrue(e instanceof CtapException);
    }

    try {
      BasicWebAuthnClient.Utils.filterCreds(
          new CtapMockBuilder().throwCtapError(true).build(),
          "wrong.com",
          Collections.emptyList(),
          RP_EXAMPLE,
          null,
          null);
    } catch (Exception e) {
      assertTrue(e instanceof ClientError);
    }

    try {
      BasicWebAuthnClient.Utils.filterCreds(
          new CtapMockBuilder().throwCtapError(true).build(),
          RP_EXAMPLE,
          Collections.emptyList(),
          "." + RP_EXAMPLE,
          null,
          null);
    } catch (Exception e) {
      assertTrue(e instanceof ClientError);
    }
  }

  private byte[] credId(int length) {
    return RandomUtils.getRandomBytes(length);
  }

  private byte[] credId(String string) {
    return string.getBytes(StandardCharsets.UTF_8);
  }

  static class CtapMockBuilder {
    @Nullable Integer maxCredentialIdLength = null;
    @Nullable Integer maxCredentialCountInList = null;
    @Nullable Map<String, List<byte[]>> credentialsForRpId = null;
    boolean throwCtapError = false;

    CtapMockBuilder maxCredentialIdLength(@Nullable Integer maxCredentialIdLength) {
      this.maxCredentialIdLength = maxCredentialIdLength;
      return this;
    }

    CtapMockBuilder maxCredentialCountInList(@Nullable Integer maxCredentialCountInList) {
      this.maxCredentialCountInList = maxCredentialCountInList;
      return this;
    }

    CtapMockBuilder credentialsForRpId(@Nullable Map<String, List<byte[]>> credentialsForRpId) {
      if (credentialsForRpId == null) {
        this.credentialsForRpId = credentialsForRpId;
      } else {
        if (this.credentialsForRpId == null) {
          this.credentialsForRpId = new HashMap<>();
        }
        this.credentialsForRpId.putAll(credentialsForRpId);
      }
      return this;
    }

    CtapMockBuilder credentialsForRpId(String rpId, byte[]... credentialIds) {
      if (this.credentialsForRpId == null) {
        this.credentialsForRpId = new HashMap<>();
      }
      this.credentialsForRpId.put(rpId, Arrays.asList(credentialIds));
      return this;
    }

    @SuppressWarnings("SameParameterValue")
    CtapMockBuilder throwCtapError(boolean throwCtapError) {
      this.throwCtapError = throwCtapError;
      return this;
    }

    Ctap2Session build() throws Throwable {

      Ctap2Session.InfoData mockInfoData = mock(Ctap2Session.InfoData.class);
      Ctap2Session ctapMock = mock(Ctap2Session.class);

      doReturn(maxCredentialIdLength).when(mockInfoData).getMaxCredentialIdLength();
      doReturn(maxCredentialCountInList).when(mockInfoData).getMaxCredentialCountInList();
      doReturn(mockInfoData).when(ctapMock).getCachedInfo();

      when(ctapMock.getAssertions(
              anyString(), any(), any(), isNull(), anyMap(), isNull(), isNull(), isNull()))
          .then(
              invocation -> {
                if (throwCtapError) {
                  throw new CtapException(CtapException.ERR_INVALID_PARAMETER);
                }

                List<byte[]> idsForRp =
                    credentialsForRpId != null
                        ? credentialsForRpId.get((String) invocation.getArgument(0))
                        : Collections.emptyList();

                List<Map<String, Object>> allowList = invocation.getArgument(2);

                List<byte[]> ids;
                if (idsForRp != null) {
                  ids = new ArrayList<>();
                  for (byte[] id : idsForRp) {
                    for (Map<String, Object> desc : allowList) {
                      byte[] descId = (byte[]) desc.get(PublicKeyCredentialDescriptor.ID);
                      if (Arrays.equals(id, descId)) {
                        ids.add(id);
                        break;
                      }
                    }
                  }
                } else {
                  ids = Collections.emptyList();
                }

                if (ids.isEmpty()) {
                  throw new CtapException(CtapException.ERR_NO_CREDENTIALS);
                }
                List<Ctap2Session.AssertionData> list = new ArrayList<>();
                for (byte[] bytes : ids) {
                  Ctap2Session.AssertionData assertionData = mock(Ctap2Session.AssertionData.class);
                  when(assertionData.getCredentialId(isNull())).thenReturn(bytes);
                  list.add(assertionData);
                }
                return list;
              });

      return ctapMock;
    }
  }
}

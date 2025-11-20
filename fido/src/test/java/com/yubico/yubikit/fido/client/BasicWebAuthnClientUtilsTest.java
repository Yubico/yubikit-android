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

package com.yubico.yubikit.fido.client;

import static com.yubico.yubikit.fido.webauthn.PublicKeyCredentialType.PUBLIC_KEY;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
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
import org.jspecify.annotations.Nullable;
import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;

@RunWith(Enclosed.class)
public class BasicWebAuthnClientUtilsTest {

  static final String RP_EXAMPLE = "example.com";

  public static class FilterCredsTests {

    @Test
    public void testOnEmptyList() throws Throwable {
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
    public void testByRpId() throws Throwable {

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
    public void testPinUvParams() throws Throwable {

      byte[] cred1 = credId("CRED1");

      Ctap2Session ctap =
          new CtapMockBuilder()
              .credentialsForRpId(RP_EXAMPLE, credId(16), cred1, credId(16))
              .build();

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
    public void testChunking() throws Throwable {
      byte[] target = credId(32);

      CtapMockBuilder ctapBuilder =
          new CtapMockBuilder().maxCredentialIdLength(64).maxCredentialCountInList(8);

      PublicKeyCredentialDescriptor dummy =
          new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(48));

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
    public void testExceptionHandling() throws Throwable {
      try {
        BasicWebAuthnClient.Utils.filterCreds(
            new CtapMockBuilder().throwCtapError(true).build(),
            RP_EXAMPLE,
            Collections.singletonList(
                new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId("TEST"))),
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

    @Test
    public void testRequestTooLargeRetry() throws Throwable {
      // Test that filterCreds handles ERR_REQUEST_TOO_LARGE by reducing chunk size
      byte[] target = credId(32);

      Ctap2Session.AssertionData mockAssertion = createMockAssertion(target);

      Ctap2Session ctap = mock(Ctap2Session.class);
      Ctap2Session.InfoData info = mock(Ctap2Session.InfoData.class);
      when(info.getMaxCredentialIdLength()).thenReturn(64);
      when(info.getMaxCredentialCountInList()).thenReturn(10);
      when(ctap.getCachedInfo()).thenReturn(info);

      PublicKeyCredentialDescriptor dummy =
          new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(48));

      // Create 10 credentials (will try to send all in first chunk)
      List<PublicKeyCredentialDescriptor> descriptors = new ArrayList<>();
      for (int i = 0; i < 9; i++) {
        descriptors.add(dummy);
      }
      descriptors.add(new PublicKeyCredentialDescriptor(PUBLIC_KEY, target));

      // First call with 10 creds throws ERR_REQUEST_TOO_LARGE
      // Second call with 9 creds succeeds
      when(ctap.getAssertions(anyString(), any(), anyList(), any(), anyMap(), any(), any(), any()))
          .thenThrow(new CtapException(CtapException.ERR_REQUEST_TOO_LARGE))
          .thenReturn(Collections.singletonList(mockAssertion));

      PublicKeyCredentialDescriptor result =
          BasicWebAuthnClient.Utils.filterCreds(ctap, null, descriptors, RP_EXAMPLE, null, null);

      assertNotNull(result);
      assertArrayEquals(target, result.getId());

      // Verify getAssertions was called twice (once with 10, once with 9)
      verify(ctap, times(2))
          .getAssertions(anyString(), any(), anyList(), any(), anyMap(), any(), any(), any());
    }

    @Test
    public void testRequestTooLargeMultipleRetries() throws Throwable {
      // Test multiple retries reducing chunk size progressively
      byte[] target = credId(32);

      Ctap2Session.AssertionData mockAssertion = createMockAssertion(target);

      Ctap2Session ctap = mock(Ctap2Session.class);
      Ctap2Session.InfoData info = mock(Ctap2Session.InfoData.class);
      when(info.getMaxCredentialIdLength()).thenReturn(64);
      when(info.getMaxCredentialCountInList()).thenReturn(5);
      when(ctap.getCachedInfo()).thenReturn(info);

      PublicKeyCredentialDescriptor dummy =
          new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(48));

      List<PublicKeyCredentialDescriptor> descriptors = new ArrayList<>();
      for (int i = 0; i < 4; i++) {
        descriptors.add(dummy);
      }
      descriptors.add(new PublicKeyCredentialDescriptor(PUBLIC_KEY, target));

      // First 3 calls throw ERR_REQUEST_TOO_LARGE (chunks: 5, 4, 3)
      // Fourth call with 2 creds succeeds
      when(ctap.getAssertions(anyString(), any(), anyList(), any(), anyMap(), any(), any(), any()))
          .thenThrow(new CtapException(CtapException.ERR_REQUEST_TOO_LARGE))
          .thenThrow(new CtapException(CtapException.ERR_REQUEST_TOO_LARGE))
          .thenThrow(new CtapException(CtapException.ERR_REQUEST_TOO_LARGE))
          .thenReturn(Collections.singletonList(mockAssertion));

      PublicKeyCredentialDescriptor result =
          BasicWebAuthnClient.Utils.filterCreds(ctap, null, descriptors, RP_EXAMPLE, null, null);

      assertNotNull(result);
      assertArrayEquals(target, result.getId());

      // Verify multiple retries occurred
      verify(ctap, times(4))
          .getAssertions(anyString(), any(), anyList(), any(), anyMap(), any(), any(), any());
    }

    @Test
    public void testRequestTooLargeReachesZero() throws Throwable {
      // Test that when maxCreds reaches 0, the exception is re-thrown
      Ctap2Session ctap = mock(Ctap2Session.class);
      Ctap2Session.InfoData info = mock(Ctap2Session.InfoData.class);
      when(info.getMaxCredentialIdLength()).thenReturn(64);
      when(info.getMaxCredentialCountInList()).thenReturn(1);
      when(ctap.getCachedInfo()).thenReturn(info);

      List<PublicKeyCredentialDescriptor> descriptors =
          Collections.singletonList(new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(32)));

      // Always throw ERR_REQUEST_TOO_LARGE
      when(ctap.getAssertions(anyString(), any(), anyList(), any(), anyMap(), any(), any(), any()))
          .thenThrow(new CtapException(CtapException.ERR_REQUEST_TOO_LARGE));

      try {
        BasicWebAuthnClient.Utils.filterCreds(ctap, null, descriptors, RP_EXAMPLE, null, null);
        fail("Expected CtapException to be thrown");
      } catch (CtapException e) {
        assertEquals(CtapException.ERR_REQUEST_TOO_LARGE, e.getCtapError());
      }

      // Verify it tried with chunk size 1, then gave up
      verify(ctap, times(1))
          .getAssertions(anyString(), any(), anyList(), any(), anyMap(), any(), any(), any());
    }

    @Test
    public void testRequestTooLargeInMiddleChunk() throws Throwable {
      // Test ERR_REQUEST_TOO_LARGE occurring in a middle chunk
      byte[] target = credId(32);

      Ctap2Session.AssertionData mockAssertion = createMockAssertion(target);

      Ctap2Session ctap = mock(Ctap2Session.class);
      Ctap2Session.InfoData info = mock(Ctap2Session.InfoData.class);
      when(info.getMaxCredentialIdLength()).thenReturn(64);
      when(info.getMaxCredentialCountInList()).thenReturn(3);
      when(ctap.getCachedInfo()).thenReturn(info);

      PublicKeyCredentialDescriptor dummy =
          new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(48));

      // 7 credentials: chunks of 3, 3, 1
      List<PublicKeyCredentialDescriptor> descriptors =
          Arrays.asList(
              dummy,
              dummy,
              dummy, // First chunk - succeeds
              dummy,
              dummy,
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, target), // Second chunk
              dummy);

      // First chunk (0-2): ERR_NO_CREDENTIALS
      // Second chunk (3-5): ERR_REQUEST_TOO_LARGE, then success with reduced size
      when(ctap.getAssertions(anyString(), any(), anyList(), any(), anyMap(), any(), any(), any()))
          .thenThrow(new CtapException(CtapException.ERR_NO_CREDENTIALS))
          .thenThrow(new CtapException(CtapException.ERR_REQUEST_TOO_LARGE))
          .thenReturn(Collections.singletonList(mockAssertion));

      PublicKeyCredentialDescriptor result =
          BasicWebAuthnClient.Utils.filterCreds(ctap, null, descriptors, RP_EXAMPLE, null, null);

      assertNotNull(result);
      assertArrayEquals(target, result.getId());

      verify(ctap, times(3))
          .getAssertions(anyString(), any(), anyList(), any(), anyMap(), any(), any(), any());
    }
  }

  public static class PreprocessCredentialListTests {
    @Test
    public void testNullAndEmptyInput() {
      List<PublicKeyCredentialDescriptor> descriptors =
          BasicWebAuthnClient.Utils.preprocessCredentialList(Collections.emptyList(), 128);
      assertTrue(descriptors.isEmpty());
    }

    @Test
    public void testFiltersUnsupportedType() {
      byte[] validCred = credId(32);
      byte[] invalidTypeCred = credId(32);

      List<PublicKeyCredentialDescriptor> descriptors =
          Arrays.asList(
              new PublicKeyCredentialDescriptor("webauthn.get", invalidTypeCred),
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, validCred));

      List<PublicKeyCredentialDescriptor> result =
          BasicWebAuthnClient.Utils.preprocessCredentialList(descriptors, 64);

      assertNotNull(result);
      // Only the public-key type should remain
      assertEquals(1, result.size());
      assertArrayEquals(validCred, result.get(0).getId());
    }

    @Test
    public void testAllCredentialsFiltered() {
      List<PublicKeyCredentialDescriptor> descriptors =
          Arrays.asList(
              new PublicKeyCredentialDescriptor("webauthn.get", credId(32)),
              new PublicKeyCredentialDescriptor("webauthn.create", credId(32)));

      List<PublicKeyCredentialDescriptor> result =
          BasicWebAuthnClient.Utils.preprocessCredentialList(descriptors, 64);

      assertTrue(result.isEmpty());

      descriptors =
          Arrays.asList(
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(129)),
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, credId(200)));

      result = BasicWebAuthnClient.Utils.preprocessCredentialList(descriptors, 128);

      assertTrue(result.isEmpty());
    }

    @Test
    public void testFiltersTooLongCredentials() {
      byte[] shortCred = credId(32);
      byte[] tooLongCred = credId(129);

      List<PublicKeyCredentialDescriptor> descriptors =
          Arrays.asList(
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, tooLongCred),
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, shortCred));

      List<PublicKeyCredentialDescriptor> result =
          BasicWebAuthnClient.Utils.preprocessCredentialList(descriptors, 128);

      assertNotNull(result);
      assertEquals(1, result.size());
      assertArrayEquals(shortCred, result.get(0).getId());
    }

    @Test
    public void testCredentialLengthBoundaries() {
      byte[] zero = new byte[0];
      byte[] atMax = credId(128);
      byte[] overMax = credId(129);

      // Zero length passes
      List<PublicKeyCredentialDescriptor> result =
          BasicWebAuthnClient.Utils.preprocessCredentialList(
              Collections.singletonList(new PublicKeyCredentialDescriptor(PUBLIC_KEY, zero)), 128);
      assertNotNull(result);
      assertEquals(1, result.size());

      // At max passes
      result =
          BasicWebAuthnClient.Utils.preprocessCredentialList(
              Collections.singletonList(new PublicKeyCredentialDescriptor(PUBLIC_KEY, atMax)), 128);
      assertNotNull(result);
      assertEquals(1, result.size());

      // Over max filtered
      result =
          BasicWebAuthnClient.Utils.preprocessCredentialList(
              Collections.singletonList(new PublicKeyCredentialDescriptor(PUBLIC_KEY, overMax)),
              128);
      assertTrue(result.isEmpty());
    }

    @Test
    public void testNoMaxLength() {
      byte[] shortCred = credId(32);
      byte[] longCred = credId(256);

      List<PublicKeyCredentialDescriptor> descriptors =
          Arrays.asList(
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, shortCred),
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, longCred));

      List<PublicKeyCredentialDescriptor> result =
          BasicWebAuthnClient.Utils.preprocessCredentialList(descriptors, null);

      assertNotNull(result);
      assertEquals(2, result.size());
    }

    @Test
    public void testStripsTransports() {
      byte[] cred = credId(32);
      List<String> transports = Arrays.asList("usb", "nfc", "ble");

      List<PublicKeyCredentialDescriptor> descriptors =
          Collections.singletonList(
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, cred, transports));

      List<PublicKeyCredentialDescriptor> result =
          BasicWebAuthnClient.Utils.preprocessCredentialList(descriptors, 128);

      assertNotNull(result);
      assertEquals(1, result.size());
      assertArrayEquals(cred, result.get(0).getId());
      // Transports should be null
      assertNull(result.get(0).getTransports());
    }

    @Test
    public void testMixedValidAndInvalid() {
      byte[] validCred1 = credId(32);
      byte[] validCred2 = credId(64);
      byte[] invalidType = credId(32);
      byte[] tooLong = credId(256);

      List<PublicKeyCredentialDescriptor> descriptors =
          Arrays.asList(
              new PublicKeyCredentialDescriptor("webauthn.create", invalidType),
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, validCred1),
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, tooLong),
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, validCred2));

      List<PublicKeyCredentialDescriptor> result =
          BasicWebAuthnClient.Utils.preprocessCredentialList(descriptors, 128);

      assertNotNull(result);
      assertEquals(2, result.size());
      assertTrue(
          Arrays.equals(validCred1, result.get(0).getId())
              || Arrays.equals(validCred1, result.get(1).getId()));
      assertTrue(
          Arrays.equals(validCred2, result.get(0).getId())
              || Arrays.equals(validCred2, result.get(1).getId()));
    }

    @Test
    public void testVaryingMaxCredIdLengths() {
      byte[] cred16 = credId(16);
      byte[] cred32 = credId(32);
      byte[] cred64 = credId(64);
      byte[] cred128 = credId(128);

      List<PublicKeyCredentialDescriptor> descriptors =
          Arrays.asList(
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, cred16),
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, cred32),
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, cred64),
              new PublicKeyCredentialDescriptor(PUBLIC_KEY, cred128));

      // Test with maxLength = 16 (only first credential)
      List<PublicKeyCredentialDescriptor> result =
          BasicWebAuthnClient.Utils.preprocessCredentialList(descriptors, 16);
      assertNotNull(result);
      assertEquals(1, result.size());
      assertArrayEquals(cred16, result.get(0).getId());

      // Test with maxLength = 32 (first two credentials)
      result = BasicWebAuthnClient.Utils.preprocessCredentialList(descriptors, 32);
      assertNotNull(result);
      assertEquals(2, result.size());

      // Test with maxLength = 64 (first three credentials)
      result = BasicWebAuthnClient.Utils.preprocessCredentialList(descriptors, 64);
      assertNotNull(result);
      assertEquals(3, result.size());

      // Test with maxLength = 255 (all credentials)
      result = BasicWebAuthnClient.Utils.preprocessCredentialList(descriptors, 255);
      assertNotNull(result);
      assertEquals(4, result.size());
    }
  }

  private static byte[] credId(int length) {
    return RandomUtils.getRandomBytes(length);
  }

  private static byte[] credId(String string) {
    return string.getBytes(StandardCharsets.UTF_8);
  }

  private static Ctap2Session.AssertionData createMockAssertion(byte[] credentialId) {
    Ctap2Session.AssertionData mockAssertion = mock(Ctap2Session.AssertionData.class);
    when(mockAssertion.getCredentialId(null)).thenReturn(credentialId);
    return mockAssertion;
  }

  static class CtapMockBuilder {
    @Nullable Integer maxCredentialIdLength = null;
    @Nullable Integer maxCredentialCountInList = null;
    @Nullable Map<String, List<byte[]>> credentialsForRpId = null;
    boolean throwCtapError = false;

    @SuppressWarnings(
        "SameParameterValue") // maxCredentialIdLength tested in PreprocessCredentialListTests
    CtapMockBuilder maxCredentialIdLength(@Nullable Integer maxCredentialIdLength) {
      this.maxCredentialIdLength = maxCredentialIdLength;
      return this;
    }

    CtapMockBuilder maxCredentialCountInList(@Nullable Integer maxCredentialCountInList) {
      this.maxCredentialCountInList = maxCredentialCountInList;
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
                  Ctap2Session.AssertionData assertionData = createMockAssertion(bytes);
                  list.add(assertionData);
                }
                return list;
              });

      return ctapMock;
    }
  }
}

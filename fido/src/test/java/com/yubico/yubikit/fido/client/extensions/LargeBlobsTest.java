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

package com.yubico.yubikit.fido.client.extensions;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.junit.Test;

public class LargeBlobsTest {
  private static final int MAX_MSG_SIZE = 1024;
  private static final int MAX_FRAGMENT = MAX_MSG_SIZE - 64;
  private static final int CAPACITY = 1024;

  private final Ctap2Session session = mock(Ctap2Session.class);

  private LargeBlobs create(Object... fragments) throws Exception {
    Ctap2Session.InfoData info = mock(Ctap2Session.InfoData.class);
    doReturn(Collections.singletonMap("largeBlobs", true)).when(info).getOptions();
    when(info.getMaxMsgSize()).thenReturn(MAX_MSG_SIZE);
    when(info.getMaxSerializedLargeBlobArray()).thenReturn(CAPACITY);
    when(session.getCachedInfo()).thenReturn(info);
    final Iterator<Object> it = Arrays.asList(fragments).iterator();
    when(session.largeBlobs(anyInt(), any(), any(), any(), any(), any()))
        .thenAnswer(
            invocation -> {
              Map<Integer, Object> map = new HashMap<>();
              map.put(1, it.next());
              return map;
            });
    return new LargeBlobs(session);
  }

  private static byte[] withDigest(byte[] data) throws Exception {
    byte[] digest = MessageDigest.getInstance("SHA-256").digest(data);
    byte[] out = Arrays.copyOf(data, data.length + 16);
    System.arraycopy(digest, 0, out, data.length, 16);
    return out;
  }

  @Test
  public void readsValidEmptyArray() throws Exception {
    // 0x80 is an empty CBOR array, the smallest valid serialized array is 17 bytes
    LargeBlobs largeBlobs = create((Object) withDigest(new byte[] {(byte) 0x80}));
    LargeBlobs.LargeBlobArray array = largeBlobs.readBlobArray();
    assertNotNull(array.entries);
    assertTrue(array.entries.isEmpty());
  }

  @Test
  public void emptyFragmentIsEmptyArray() throws Exception {
    assertNull(create((Object) new byte[0]).readBlobArray().entries);
  }

  @Test
  public void arrayShorterThanTrailerIsEmptyArray() throws Exception {
    assertNull(create((Object) new byte[15]).readBlobArray().entries);
  }

  @Test
  public void capacityBoundaryIsAccepted() throws Exception {
    byte[] first = new byte[MAX_FRAGMENT];
    byte[] second = new byte[CAPACITY - MAX_FRAGMENT];
    // Digest does not match, which is an empty array rather than an error
    assertNull(create(first, second).readBlobArray().entries);
    verify(session, times(2)).largeBlobs(anyInt(), any(), any(), any(), any(), any());
  }

  @Test
  public void repeatedFullFragmentsStopAtCapacity() throws Exception {
    byte[] full = new byte[MAX_FRAGMENT];
    // Endless supply of full fragments, only the first two may be requested
    LargeBlobs largeBlobs = create(full, full, full, full, full);
    assertThrows(BadResponseException.class, largeBlobs::readBlobArray);
    verify(session, times(2)).largeBlobs(anyInt(), any(), any(), any(), any(), any());
  }

  @Test
  public void fragmentLargerThanRequestedIsRejected() throws Exception {
    LargeBlobs largeBlobs = create((Object) new byte[MAX_FRAGMENT + 1]);
    assertThrows(BadResponseException.class, largeBlobs::readBlobArray);
  }

  @Test
  public void fragmentOfWrongTypeIsRejected() throws Exception {
    LargeBlobs largeBlobs = create((Object) "not bytes");
    assertThrows(BadResponseException.class, largeBlobs::readBlobArray);
  }
}

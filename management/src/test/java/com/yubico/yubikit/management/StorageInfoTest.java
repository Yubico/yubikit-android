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

package com.yubico.yubikit.management;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertThrows;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.util.Tlv;
import java.io.ByteArrayOutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import org.junit.Test;

public class StorageInfoTest {

  /** Typical response, taken from the yubikey-manager reference tests. */
  static final byte[] STORAGE_RESPONSE =
      bytes(
          0x01, 0x1e, 0x00, 0x00, 0x91, 0x01, 0x95, 0x01, 0x00, 0x02, 0x00, 0x07, 0x02, 0x00, 0x03,
          0x00, 0x18, 0x03, 0x00, 0x04, 0x00, 0x20, 0x04, 0x00, 0x06, 0x00, 0x0c, 0x05, 0x00, 0x00,
          0x00, 0x00);

  static final StorageInfo STORAGE_INFO =
      new StorageInfo(
          Arrays.asList(
              new StorageInfo.Entry(0, 145, 405),
              new StorageInfo.Entry(1, 2, 7),
              new StorageInfo.Entry(2, 3, 24),
              new StorageInfo.Entry(3, 4, 32),
              new StorageInfo.Entry(4, 6, 12),
              new StorageInfo.Entry(5, 0, 0)));

  static byte[] bytes(int... values) {
    byte[] result = new byte[values.length];
    for (int i = 0; i < values.length; i++) {
      result[i] = (byte) values[i];
    }
    return result;
  }

  private static byte[] concat(byte[]... parts) {
    ByteArrayOutputStream stream = new ByteArrayOutputStream();
    for (byte[] part : parts) {
      stream.write(part, 0, part.length);
    }
    return stream.toByteArray();
  }

  @Test
  public void parsesTypicalResponse() throws Exception {
    StorageInfo info = StorageInfo.parse(STORAGE_RESPONSE);
    assertEquals(STORAGE_INFO, info);
    assertEquals(STORAGE_INFO.hashCode(), info.hashCode());

    StorageInfo.Entry free = info.getEntry(StorageInfo.ID_FREE);
    assertSame(info.getEntries().get(0), free);
    assertEquals(0, free.getId());
    assertEquals(145, free.getObjects());
    assertEquals(405, free.getPages());
    assertSame(info.getEntries().get(5), info.getEntry(5));
    assertNull(info.getEntry(99));
  }

  @Test
  public void preservesUnknownIdsAndInlineObjects() throws Exception {
    StorageInfo info =
        StorageInfo.parse(
            new Tlv(0x01, bytes(0xff, 0xff, 0xff, 0xff, 0xff, 1, 0, 1, 0, 0)).getBytes());
    assertEquals(
        Arrays.asList(new StorageInfo.Entry(0xff, 0xffff, 0xffff), new StorageInfo.Entry(1, 1, 0)),
        info.getEntries());
  }

  @Test
  public void returnsFirstEntryForRepeatedId() throws Exception {
    StorageInfo info =
        StorageInfo.parse(new Tlv(0x01, bytes(7, 0, 1, 0, 2, 7, 0, 3, 0, 4)).getBytes());
    assertEquals(2, info.getEntries().size());
    assertEquals(new StorageInfo.Entry(7, 1, 2), info.getEntry(7));
  }

  @Test
  public void parsesEmptyPayload() throws Exception {
    StorageInfo info = StorageInfo.parse(bytes(0x01, 0x00));
    assertEquals(new StorageInfo(Collections.<StorageInfo.Entry>emptyList()), info);
    assertNull(info.getEntry(StorageInfo.ID_FREE));
  }

  @Test
  public void parsesLongFormLengths() throws Exception {
    for (int count : new int[] {26, 60}) {
      ByteArrayOutputStream payload = new ByteArrayOutputStream();
      for (int id = 0; id < count; id++) {
        payload.write(bytes(id, 0, id, 0, 1), 0, 5);
      }
      byte[] encoded = new Tlv(0x01, payload.toByteArray()).getBytes();
      // 130 bytes use the 0x81 form, 300 bytes the 0x82 form.
      assertEquals(count == 26 ? 0x81 : 0x82, encoded[1] & 0xff);

      StorageInfo info = StorageInfo.parse(encoded);
      assertEquals(count, info.getEntries().size());
      assertEquals(new StorageInfo.Entry(count - 1, count - 1, 1), info.getEntry(count - 1));
    }
  }

  @Test
  public void ignoresUnknownTlvs() throws Exception {
    byte[] extra = new Tlv(0x7f49, new byte[128]).getBytes();
    byte[] metadata = new Tlv(0x02, bytes('m', 'e', 't', 'a')).getBytes();
    for (byte[] encoded :
        Arrays.asList(
            concat(extra, STORAGE_RESPONSE),
            concat(STORAGE_RESPONSE, extra),
            concat(extra, STORAGE_RESPONSE, extra),
            concat(metadata, STORAGE_RESPONSE, metadata))) {
      assertEquals(STORAGE_INFO, StorageInfo.parse(encoded));
    }
  }

  @Test
  public void rejectsMissingStorageTlv() {
    for (byte[] encoded :
        Arrays.asList(bytes(), bytes(0x02, 0x00), bytes(0x02, 0x00, 0x03, 0x00))) {
      assertBadResponse(encoded);
    }
  }

  @Test
  public void rejectsDuplicateStorageTlv() {
    assertBadResponse(bytes(0x01, 0x00, 0x01, 0x00));
    assertBadResponse(bytes(0x01, 0x00, 0x02, 0x00, 0x01, 0x00));
    assertBadResponse(concat(STORAGE_RESPONSE, STORAGE_RESPONSE));
  }

  @Test
  public void rejectsBadTlvEncoding() {
    for (byte[] encoded :
        Arrays.asList(
            bytes(0x01), // missing length
            bytes(0x01, 0x05, 0x00), // value shorter than length
            bytes(0x01, 0x00, 0xff), // truncated trailing multi-byte tag
            bytes(0x01, 0x00, 0x02, 0x01), // truncated trailing TLV
            bytes(0x02, 0x01), // truncated unknown TLV
            bytes(0x01, 0x80), // indefinite length
            bytes(0x01, 0x85, 0, 0, 0, 0, 5))) { // over-long length field
      assertBadResponse(encoded);
    }
  }

  @Test
  public void rejectsPayloadNotMultipleOfFive() {
    for (int size : new int[] {1, 2, 3, 4, 6, 7, 8, 9}) {
      assertBadResponse(new Tlv(0x01, new byte[size]).getBytes());
    }
  }

  @Test
  public void entriesAreUnmodifiableAndCopied() {
    List<StorageInfo.Entry> source = new ArrayList<>();
    source.add(new StorageInfo.Entry(0, 1, 2));
    StorageInfo info = new StorageInfo(source);
    source.add(new StorageInfo.Entry(1, 1, 1));

    assertEquals(1, info.getEntries().size());
    assertThrows(
        UnsupportedOperationException.class,
        () -> info.getEntries().add(new StorageInfo.Entry(2, 0, 0)));
  }

  @Test
  public void entryRejectsOutOfRangeValues() {
    assertThrows(IllegalArgumentException.class, () -> new StorageInfo.Entry(-1, 0, 0));
    assertThrows(IllegalArgumentException.class, () -> new StorageInfo.Entry(0x100, 0, 0));
    assertThrows(IllegalArgumentException.class, () -> new StorageInfo.Entry(0, -1, 0));
    assertThrows(IllegalArgumentException.class, () -> new StorageInfo.Entry(0, 0x10000, 0));
    assertThrows(IllegalArgumentException.class, () -> new StorageInfo.Entry(0, 0, -1));
    assertThrows(IllegalArgumentException.class, () -> new StorageInfo.Entry(0, 0, 0x10000));
  }

  @Test
  public void toStringListsEntries() {
    assertEquals(
        "StorageInfo{entries=[Entry{id=0, objects=145, pages=405}]}",
        new StorageInfo(Collections.singletonList(new StorageInfo.Entry(0, 145, 405))).toString());
  }

  private static void assertBadResponse(byte[] encoded) {
    assertThrows(
        "Expected BadResponseException for " + Arrays.toString(encoded),
        BadResponseException.class,
        () -> StorageInfo.parse(encoded));
  }
}

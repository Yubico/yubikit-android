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

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Objects;
import org.jspecify.annotations.Nullable;

/**
 * Shared-storage statistics reported by the YubiKey.
 *
 * <p>The storage is reported as a list of {@link Entry entries}, in the order reported by the
 * device. The entry with id {@code 0} holds the free object slots and free storage pages. All other
 * ids are object types defined by the firmware; ids which are not known to this SDK are kept as
 * reported.
 *
 * <p>Object slots and storage pages are independent resources: an object stored inline occupies an
 * object slot without using any storage pages.
 *
 * @see ManagementSession#readStorageInfo()
 */
public final class StorageInfo {
  /** The id of the entry holding free object slots and free storage pages. */
  public static final int ID_FREE = 0;

  static final int TAG_STORAGE_INFO = 0x01;
  private static final int ENTRY_SIZE = 5;

  private final List<Entry> entries;

  /**
   * Constructs a new StorageInfo.
   *
   * @param entries the storage entries, in the order reported by the device
   */
  public StorageInfo(List<Entry> entries) {
    this.entries = Collections.unmodifiableList(new ArrayList<>(entries));
  }

  /**
   * Returns all storage entries, in the order reported by the device.
   *
   * @return an unmodifiable list of entries
   */
  public List<Entry> getEntries() {
    return entries;
  }

  /**
   * Returns the first entry with the given id.
   *
   * @param id the object type id, or {@link #ID_FREE} for free space
   * @return the first entry with the given id, or null if the device did not report it
   */
  public @Nullable Entry getEntry(int id) {
    for (Entry entry : entries) {
      if (entry.id == id) {
        return entry;
      }
    }
    return null;
  }

  /**
   * Parses a storage info response.
   *
   * <p>The response must contain exactly one TLV with tag {@code 0x01}, whose value is a sequence
   * of 5-byte records: id (1 byte), objects (2 bytes, big-endian) and pages (2 bytes, big-endian).
   * Additional well-formed TLVs with other tags are ignored.
   *
   * @param response the encoded response
   * @return the parsed StorageInfo
   * @throws BadResponseException if the response is malformed
   */
  static StorageInfo parse(byte[] response) throws BadResponseException {
    List<Tlv> tlvs;
    try {
      tlvs = Tlvs.decodeList(response);
    } catch (IllegalArgumentException | BufferUnderflowException e) {
      throw new BadResponseException("Malformed storage info TLV encoding", e);
    }

    byte[] payload = null;
    for (Tlv tlv : tlvs) {
      if (tlv.getTag() == TAG_STORAGE_INFO) {
        if (payload != null) {
          throw new BadResponseException("Duplicate storage info TLV with tag 0x01");
        }
        payload = tlv.getValue();
      }
    }
    if (payload == null) {
      throw new BadResponseException("Missing storage info TLV with tag 0x01");
    }
    if (payload.length % ENTRY_SIZE != 0) {
      throw new BadResponseException(
          String.format(
              Locale.ROOT,
              "Storage info length %d is not a multiple of %d",
              payload.length,
              ENTRY_SIZE));
    }

    ByteBuffer buffer = ByteBuffer.wrap(payload);
    List<Entry> entries = new ArrayList<>(payload.length / ENTRY_SIZE);
    while (buffer.hasRemaining()) {
      entries.add(
          new Entry(buffer.get() & 0xff, buffer.getShort() & 0xffff, buffer.getShort() & 0xffff));
    }
    return new StorageInfo(entries);
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    StorageInfo that = (StorageInfo) o;
    return entries.equals(that.entries);
  }

  @Override
  public int hashCode() {
    return entries.hashCode();
  }

  @Override
  public String toString() {
    return "StorageInfo{" + "entries=" + entries + '}';
  }

  /** Storage usage for one object type id. */
  public static final class Entry {
    private final int id;
    private final int objects;
    private final int pages;

    /**
     * Constructs a new storage entry.
     *
     * @param id the object type id (0-255), {@link #ID_FREE} for free space
     * @param objects the number of objects, or free object slots for {@link #ID_FREE} (0-65535)
     * @param pages the number of storage pages, or free pages for {@link #ID_FREE} (0-65535)
     * @throws IllegalArgumentException if a value is out of range
     */
    public Entry(int id, int objects, int pages) {
      if (id < 0 || id > 0xff) {
        throw new IllegalArgumentException("Invalid id: " + id);
      }
      if (objects < 0 || objects > 0xffff) {
        throw new IllegalArgumentException("Invalid objects: " + objects);
      }
      if (pages < 0 || pages > 0xffff) {
        throw new IllegalArgumentException("Invalid pages: " + pages);
      }
      this.id = id;
      this.objects = objects;
      this.pages = pages;
    }

    /**
     * Returns the object type id.
     *
     * <p>Id {@link #ID_FREE} denotes free space. Other ids are object types defined by the
     * firmware.
     *
     * @return the id (0-255)
     */
    public int getId() {
      return id;
    }

    /**
     * Returns the number of objects of this type, or the number of free object slots for {@link
     * #ID_FREE}.
     *
     * @return the object count (0-65535)
     */
    public int getObjects() {
      return objects;
    }

    /**
     * Returns the number of storage pages used by objects of this type, or the number of free pages
     * for {@link #ID_FREE}.
     *
     * <p>Objects stored inline occupy an object slot without using pages.
     *
     * @return the page count (0-65535)
     */
    public int getPages() {
      return pages;
    }

    @Override
    public boolean equals(Object o) {
      if (this == o) return true;
      if (o == null || getClass() != o.getClass()) return false;
      Entry that = (Entry) o;
      return id == that.id && objects == that.objects && pages == that.pages;
    }

    @Override
    public int hashCode() {
      return Objects.hash(id, objects, pages);
    }

    @Override
    public String toString() {
      return "Entry{" + "id=" + id + ", objects=" + objects + ", pages=" + pages + '}';
    }
  }
}

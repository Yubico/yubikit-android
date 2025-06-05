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

package com.yubico.yubikit.fido.client.extensions;

import com.yubico.yubikit.core.application.CommandException;
import com.yubico.yubikit.core.util.RandomUtils;
import com.yubico.yubikit.fido.Cbor;
import com.yubico.yubikit.fido.ctap.Ctap2Session;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterInputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import javax.annotation.Nullable;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class LargeBlobs {

  private final Ctap2Session session;
  private final int maxFragmentLen;

  @Nullable final PinUvAuthProtocol pinUvAuthProtocol;
  @Nullable final byte[] pinUvAuthToken;

  LargeBlobs(Ctap2Session session) {
    this(session, null, null);
  }

  LargeBlobs(
      Ctap2Session session,
      @Nullable PinUvAuthProtocol pinUvAuthProtocol,
      @Nullable byte[] pinUvAuthToken) {

    final Ctap2Session.InfoData info = session.getCachedInfo();

    if (!isSupported(info)) {
      throw new IllegalStateException("Authenticator does not support large blobs");
    }

    this.session = session;
    this.maxFragmentLen = info.getMaxMsgSize() - 64;

    if (pinUvAuthToken != null && pinUvAuthProtocol != null) {
      this.pinUvAuthProtocol = pinUvAuthProtocol;
      this.pinUvAuthToken = pinUvAuthToken;
    } else {
      this.pinUvAuthProtocol = null;
      this.pinUvAuthToken = null;
    }
  }

  static boolean isSupported(Ctap2Session.InfoData info) {
    return Boolean.TRUE.equals(info.getOptions().get("largeBlobs"));
  }

  LargeBlobArray readBlobArray() throws IOException, CommandException {
    int offset = 0;
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    while (true) {
      Map<Integer, ?> map = session.largeBlobs(offset, maxFragmentLen, null, null, null, null);
      if (!map.containsKey(1)) {
        return LargeBlobArray.empty();
      }

      byte[] fragment = (byte[]) map.get(1);
      os.write(fragment);

      if (fragment.length < maxFragmentLen) {
        break;
      }
      offset += fragment.length;
    }
    byte[] buffer = os.toByteArray();
    byte[] data = Arrays.copyOf(buffer, buffer.length - 16);
    byte[] digest = hash(data);
    if (!Arrays.equals(
        Arrays.copyOfRange(buffer, buffer.length - 16, buffer.length),
        Arrays.copyOf(digest, digest.length - 16))) {
      return LargeBlobArray.empty();
    }

    return LargeBlobArray.fromBytes(data);
  }

  void writeBlobArray(LargeBlobArray largeBlobArray) throws IOException, CommandException {
    final byte[] data = largeBlobArray.toBytes();

    byte[] dataWithHash =
        ByteBuffer.allocate(data.length + 16).put(data).put(hash(data), 0, 16).array();

    int offset = 0;
    int size = dataWithHash.length;
    while (offset < size) {
      int ln = Math.min(size - offset, maxFragmentLen);
      byte[] fragment = Arrays.copyOfRange(dataWithHash, offset, offset + ln);

      Integer pinUvAuthProtocolVersion = null;
      byte[] pinUvAuthParam = null;

      if (pinUvAuthToken != null && pinUvAuthProtocol != null) {
        byte[] msg = fragmentMessage(offset, fragment);
        pinUvAuthProtocolVersion = this.pinUvAuthProtocol.getVersion();
        pinUvAuthParam = pinUvAuthProtocol.authenticate(pinUvAuthToken, msg);
      }

      session.largeBlobs(
          offset,
          null,
          fragment,
          offset == 0 ? size : null,
          pinUvAuthParam,
          pinUvAuthProtocolVersion);

      offset += ln;
    }
  }

  private static final byte[] fragmentMessagePrefix = new byte[32];

  static {
    Arrays.fill(fragmentMessagePrefix, (byte) 0xff);
  }

  private byte[] fragmentMessage(int offset, byte[] fragment) {
    return ByteBuffer.allocate(70)
        .put(fragmentMessagePrefix)
        .put((byte) 0x0c)
        .put((byte) 0x00)
        .order(ByteOrder.LITTLE_ENDIAN)
        .putInt(offset)
        .put(hash(fragment))
        .array();
  }

  @Nullable
  byte[] getBlob(byte[] largeBlobKey) throws IOException, CommandException {
    for (LargeBlobMap entry : readBlobArray()) {
      try {
        byte[] blob = CompressionUtils.decompress(unpack(largeBlobKey, entry));
        if (blob.length == entry.getOrigSize()) {
          return blob;
        }
      } catch (GeneralSecurityException ignoredException) {
        // ignoring this entry
      }
    }
    return null;
  }

  void putBlob(byte[] largeBlobKey, @Nullable byte[] data)
      throws IOException, CommandException, GeneralSecurityException {
    boolean modified = data != null;
    LargeBlobArray blobArray = readBlobArray();
    List<LargeBlobMap> entries = new ArrayList<>();
    for (LargeBlobMap largeBlobMap : blobArray) {
      try {
        unpack(largeBlobKey, largeBlobMap);
        modified = true;
      } catch (Exception e) {
        entries.add(largeBlobMap);
      }
    }

    if (data != null) {
      entries.add(pack(largeBlobKey, data));
    }

    if (modified) {
      writeBlobArray(new LargeBlobArray(entries));
    }
  }

  private byte[] unpack(byte[] key, final LargeBlobMap largeBlobMap)
      throws GeneralSecurityException {
    return AesGcm.decrypt(
        key,
        largeBlobMap.getNonce(),
        largeBlobMap.getCiphertext(),
        associatedData(largeBlobMap.getOrigSize()));
  }

  private LargeBlobMap pack(byte[] key, byte[] data) throws IOException, GeneralSecurityException {
    int origSize = data.length;
    byte[] nonce = RandomUtils.getRandomBytes(12);
    byte[] ciphertext =
        AesGcm.encrypt(key, nonce, CompressionUtils.compress(data), associatedData(origSize));

    return new LargeBlobMap(ciphertext, nonce, origSize);
  }

  private byte[] associatedData(int origSize) {
    return ByteBuffer.allocate(12)
        .order(ByteOrder.BIG_ENDIAN)
        .putInt(0x626c6f62) // blob
        .order(ByteOrder.LITTLE_ENDIAN)
        .putLong(origSize)
        .array();
  }

  static class LargeBlobArray implements Iterable<LargeBlobMap> {

    @Nullable final List<LargeBlobMap> entries;

    private LargeBlobArray(@Nullable final List<LargeBlobMap> entries) {
      this.entries = entries;
    }

    static LargeBlobArray empty() {
      return new LargeBlobArray(null);
    }

    static LargeBlobArray fromBytes(byte[] cbor) {
      try {
        @SuppressWarnings("unchecked")
        List<Map<Integer, Object>> list = (List<Map<Integer, Object>>) Cbor.decode(cbor);
        if (list == null) {
          return empty();
        }
        final List<LargeBlobMap> entries = new ArrayList<>();
        for (Map<Integer, Object> entry : list) {
          LargeBlobMap largeBlobMap = LargeBlobMap.fromMap(entry);
          if (largeBlobMap != null) {
            // only add conforming items
            entries.add(largeBlobMap);
          }
        }
        return new LargeBlobArray(entries);
      } catch (Exception e) {
        return empty();
      }
    }

    byte[] toBytes() {
      if (entries == null) {
        return new byte[0];
      }

      List<Map<Integer, Object>> largeBlobs = new ArrayList<>();
      for (LargeBlobMap map : entries) {
        largeBlobs.add(map.toMap());
      }

      return Cbor.encode(largeBlobs);
    }

    @Override
    public Iterator<LargeBlobMap> iterator() {
      return new Iterator<LargeBlobMap>() {

        private int currentIndex = 0;

        @Override
        public boolean hasNext() {
          return entries != null && currentIndex < entries.size();
        }

        @Override
        public LargeBlobMap next() {
          if (entries == null || currentIndex >= entries.size()) {
            throw new NoSuchElementException();
          }
          return entries.get(currentIndex++);
        }
      };
    }
  }

  static class LargeBlobMap {
    private static final int CIPHERTEXT = 1;
    private static final int NONCE = 2;
    private static final int ORIG_SIZE = 3;

    private final Map<Integer, Object> data;

    private LargeBlobMap(byte[] ciphertext, byte[] nonce, int origSize) {
      data = new HashMap<>();
      data.put(CIPHERTEXT, ciphertext);
      data.put(NONCE, nonce);
      data.put(ORIG_SIZE, origSize);
    }

    Map<Integer, Object> toMap() {
      return data;
    }

    @Nullable
    static LargeBlobMap fromMap(Map<Integer, Object> map) {
      byte[] ciphertext = (byte[]) map.get(CIPHERTEXT);
      byte[] nonce = (byte[]) map.get(NONCE);
      Integer origSize = (Integer) map.get(ORIG_SIZE);

      if (ciphertext == null || nonce == null || origSize == null) {
        // does not conform large-blob map
        return null;
      }

      return new LargeBlobMap(ciphertext, nonce, origSize);
    }

    byte[] getCiphertext() {
      return (byte[]) data.get(CIPHERTEXT);
    }

    byte[] getNonce() {
      return (byte[]) data.get(NONCE);
    }

    int getOrigSize() {
      return (int) data.get(ORIG_SIZE);
    }
  }

  static class CompressionUtils {
    static byte[] decompress(byte[] data) throws IOException {
      ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
      InflaterInputStream inflaterInputStream =
          new InflaterInputStream(inputStream, new Inflater(true));
      return process(inflaterInputStream);
    }

    static byte[] compress(byte[] input) throws IOException {
      ByteArrayInputStream inputStream = new ByteArrayInputStream(input);
      DeflaterInputStream deflaterInputStream =
          new DeflaterInputStream(inputStream, new Deflater(-1, true));
      return process(deflaterInputStream);
    }

    private static byte[] process(FilterInputStream filterInputStream) throws IOException {
      ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
      byte[] buf = new byte[255];
      int len;
      while ((len = filterInputStream.read(buf)) != -1) {
        outputStream.write(buf, 0, len);
      }
      return outputStream.toByteArray();
    }
  }

  static class AesGcm {
    static byte[] decrypt(byte[] key, byte[] nonce, byte[] data, byte[] associatedData)
        throws GeneralSecurityException {
      return process(Cipher.DECRYPT_MODE, key, nonce, data, associatedData);
    }

    static byte[] encrypt(byte[] key, byte[] nonce, byte[] data, byte[] associatedData)
        throws GeneralSecurityException {
      return process(Cipher.ENCRYPT_MODE, key, nonce, data, associatedData);
    }

    private static byte[] process(
        int mode, byte[] key, byte[] nonce, byte[] ciphertext, byte[] associatedData)
        throws GeneralSecurityException {
      Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
      SecretKeySpec k = new SecretKeySpec(key, "AES");
      GCMParameterSpec p = new GCMParameterSpec(128, nonce);
      c.init(mode, k, p);
      c.updateAAD(associatedData);
      c.update(ciphertext);
      return c.doFinal();
    }
  }

  static byte[] hash(byte[] message) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(message);
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
  }
}

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
package com.yubico.yubikit.core.util;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Arrays;

/**
 * A {@link java.io.ByteArrayOutputStream} replacement that zeros its internal buffer on {@link
 * #close()} and {@link #reset()}.
 */
public final class SecureByteArrayOutputStream extends OutputStream {
  private byte[] buf;
  private int count;
  private boolean closed = false;

  /** Creates a new instance with the default initial capacity of 32 bytes. */
  public SecureByteArrayOutputStream() {
    this(32);
  }

  /** Creates a new instance with the specified initial capacity. */
  public SecureByteArrayOutputStream(int initialCapacity) {
    this.buf = new byte[initialCapacity];
    this.count = 0;
  }

  private void ensureCapacity(int minCapacity) {
    if (minCapacity > buf.length) {
      int newCapacity = Math.max(buf.length * 2, minCapacity);
      byte[] newBuf = new byte[newCapacity];
      System.arraycopy(buf, 0, newBuf, 0, count);
      Arrays.fill(buf, (byte) 0);
      buf = newBuf;
    }
  }

  @Override
  public void write(int b) {
    ensureCapacity(count + 1);
    buf[count] = (byte) b;
    count++;
  }

  @Override
  public void write(byte[] b, int off, int len) {
    ensureCapacity(count + len);
    System.arraycopy(b, off, buf, count, len);
    count += len;
  }

  /** Returns a copy of the data written so far. */
  public byte[] toByteArray() {
    return Arrays.copyOf(buf, count);
  }

  /** Returns the current number of bytes written. */
  public int size() {
    return count;
  }

  /** Zeros the internal buffer contents and resets the position to 0. */
  public void reset() {
    Arrays.fill(buf, 0, count, (byte) 0);
    count = 0;
  }

  /** Zeros the internal buffer. Idempotent. */
  @Override
  public void close() {
    if (!closed) {
      Arrays.fill(buf, (byte) 0);
      closed = true;
    }
  }

  /** Writes the contents to another stream. */
  public void writeTo(OutputStream out) throws IOException {
    out.write(buf, 0, count);
  }
}

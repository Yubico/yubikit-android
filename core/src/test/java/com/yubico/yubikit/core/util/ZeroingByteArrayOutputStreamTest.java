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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import org.junit.Assert;
import org.junit.Test;

public class ZeroingByteArrayOutputStreamTest {
  @Test
  public void testWriteSingleByte() {
    ZeroingByteArrayOutputStream out = new ZeroingByteArrayOutputStream();
    out.write(0x42);
    Assert.assertEquals(1, out.size());
    Assert.assertArrayEquals(new byte[] {0x42}, out.toByteArray());
    out.close();
  }

  @Test
  public void testWriteByteArray() {
    ZeroingByteArrayOutputStream out = new ZeroingByteArrayOutputStream();
    out.write(new byte[] {1, 2, 3, 4, 5}, 1, 3);
    Assert.assertEquals(3, out.size());
    Assert.assertArrayEquals(new byte[] {2, 3, 4}, out.toByteArray());
    out.close();
  }

  @Test
  public void testToByteArrayReturnsCopy() {
    ZeroingByteArrayOutputStream out = new ZeroingByteArrayOutputStream();
    out.write(1);
    byte[] a = out.toByteArray();
    byte[] b = out.toByteArray();
    Assert.assertArrayEquals(a, b);
    Assert.assertNotSame(a, b);
    out.close();
  }

  @Test
  public void testResetZerosAndResetsPosition() {
    ZeroingByteArrayOutputStream out = new ZeroingByteArrayOutputStream(4);
    out.write(new byte[] {1, 2, 3, 4}, 0, 4);
    byte[] before = out.toByteArray();
    Assert.assertArrayEquals(new byte[] {1, 2, 3, 4}, before);
    out.reset();
    Assert.assertEquals(0, out.size());
    Assert.assertArrayEquals(new byte[0], out.toByteArray());
    out.close();
  }

  @Test
  public void testCloseZerosBuffer() {
    ZeroingByteArrayOutputStream out = new ZeroingByteArrayOutputStream(4);
    out.write(new byte[] {1, 2, 3, 4}, 0, 4);
    out.close();
    // count is still 4, but buf is zeroed — toByteArray returns zeroed copy
    Assert.assertArrayEquals(new byte[] {0, 0, 0, 0}, out.toByteArray());
    // idempotent
    out.close();
  }

  @Test
  public void testDoubleCloseIsSafe() {
    ZeroingByteArrayOutputStream out = new ZeroingByteArrayOutputStream();
    out.write(42);
    out.close();
    out.close();
  }

  @Test
  public void testBufferGrowthZerosOldBuffer() {
    // Start with small capacity to force growth
    ZeroingByteArrayOutputStream out = new ZeroingByteArrayOutputStream(2);
    out.write(new byte[] {1, 2, 3, 4, 5}, 0, 5);
    Assert.assertEquals(5, out.size());
    Assert.assertArrayEquals(new byte[] {1, 2, 3, 4, 5}, out.toByteArray());
    out.close();
  }

  @Test
  public void testWriteTo() throws IOException {
    ZeroingByteArrayOutputStream out = new ZeroingByteArrayOutputStream();
    out.write(new byte[] {10, 20, 30}, 0, 3);
    ByteArrayOutputStream target = new ByteArrayOutputStream();
    out.writeTo(target);
    Assert.assertArrayEquals(new byte[] {10, 20, 30}, target.toByteArray());
    out.close();
  }

  @Test
  public void testWriteFullByteArray() throws IOException {
    ZeroingByteArrayOutputStream out = new ZeroingByteArrayOutputStream();
    out.write(new byte[] {1, 2, 3});
    Assert.assertEquals(3, out.size());
    Assert.assertArrayEquals(new byte[] {1, 2, 3}, out.toByteArray());
    out.close();
  }

  @Test
  public void testDefaultCapacity() {
    ZeroingByteArrayOutputStream out = new ZeroingByteArrayOutputStream();
    // Should be able to write at least 32 bytes without growth
    byte[] data = new byte[32];
    for (int i = 0; i < 32; i++) {
      data[i] = (byte) i;
    }
    out.write(data, 0, 32);
    Assert.assertEquals(32, out.size());
    Assert.assertArrayEquals(data, out.toByteArray());
    out.close();
  }
}

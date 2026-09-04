/*
 * Copyright (C) 2020-2022 Yubico.
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

import com.yubico.yubikit.core.application.BadResponseException;
import java.nio.BufferUnderflowException;
import org.junit.Assert;
import org.junit.Test;

public class TlvsTest {
  @Test
  public void testDoubleByteTags() {
    Tlv tlv = Tlv.parse(new byte[] {0x7F, 0x49, 0});
    Assert.assertEquals(0x7F49, tlv.getTag());
    Assert.assertEquals(0, tlv.getLength());

    tlv = Tlv.parse(new byte[] {(byte) 0x80, 0});
    Assert.assertEquals(0x80, tlv.getTag());
    Assert.assertEquals(0, tlv.getLength());

    tlv = new Tlv(0x7F49, null);
    Assert.assertEquals(0x7F49, tlv.getTag());
    Assert.assertEquals(0, tlv.getLength());
    Assert.assertArrayEquals(new byte[] {0x7F, 0x49, 0}, tlv.getBytes());

    tlv = new Tlv(0x80, null);
    Assert.assertEquals(0x80, tlv.getTag());
    Assert.assertEquals(0, tlv.getLength());
    Assert.assertArrayEquals(new byte[] {(byte) 0x80, 0}, tlv.getBytes());
  }

  @Test
  public void testUnwrap() throws BadResponseException {
    Tlvs.unpackValue(0x80, new byte[] {(byte) 0x80, 0});

    Tlvs.unpackValue(0x7F49, new byte[] {0x7F, 0x49, 0});

    byte[] value = Tlvs.unpackValue(0x7F49, new byte[] {0x7F, 0x49, 3, 1, 2, 3});
    Assert.assertArrayEquals(new byte[] {1, 2, 3}, value);
  }

  /**
   * A declared length larger than the data actually present must report a truncated response rather
   * than allocating first. Allocating first raises an OutOfMemoryError, which is an {@link Error}
   * and so escapes callers that recover from BufferUnderflowException.
   */
  @Test(expected = BufferUnderflowException.class)
  public void testOversizedLengthDoesNotAllocate() {
    // Long form length of 0x7FFFFFFF in a six byte buffer.
    Tlv.parse(new byte[] {0x01, (byte) 0x84, 0x7F, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
  }

  @Test(expected = BufferUnderflowException.class)
  public void testShortFormLengthPastEndOfBuffer() {
    Tlv.parse(new byte[] {0x01, 0x10, 0x00});
  }

  /**
   * Five length bytes overflow the int the length is accumulated into. Before this was rejected the
   * value below wrapped to zero and parsed as an empty, valid looking Tlv.
   */
  @Test(expected = IllegalArgumentException.class)
  public void testLengthWithTooManyBytes() {
    Tlv.parse(new byte[] {0x01, (byte) 0x85, 0x01, 0x00, 0x00, 0x00, 0x00});
  }

  /** A length above Integer.MAX_VALUE previously reached {@code new byte[-1]}. */
  @Test(expected = IllegalArgumentException.class)
  public void testLengthAboveIntegerMaxValue() {
    Tlv.parse(new byte[] {0x01, (byte) 0x84, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF});
  }

  /** A long form tag whose continuation bit never clears would silently overflow the tag int. */
  @Test(expected = IllegalArgumentException.class)
  public void testUnterminatedLongFormTag() {
    Tlv.parse(new byte[] {0x1F, (byte) 0x81, (byte) 0x81, (byte) 0x81, (byte) 0x81, 0x00});
  }

  /** Four byte tags are still in range, so the bound cannot break real responses. */
  @Test
  public void testMaxLengthTagIsAccepted() {
    Tlv tlv = Tlv.parse(new byte[] {0x1F, (byte) 0x81, (byte) 0x81, 0x01, 0x00});
    Assert.assertEquals(0x1F818101, tlv.getTag());
    Assert.assertEquals(0, tlv.getLength());
  }

  /** Four length bytes are the widest a valid length can be, and must still parse. */
  @Test
  public void testFourByteLengthIsAccepted() {
    Tlv tlv = Tlv.parse(new byte[] {0x01, (byte) 0x84, 0x00, 0x00, 0x00, 0x03, 1, 2, 3});
    Assert.assertEquals(3, tlv.getLength());
    Assert.assertArrayEquals(new byte[] {1, 2, 3}, tlv.getValue());
  }

  /** Truncation partway through a sequence must not yield a silently short list. */
  @Test(expected = BufferUnderflowException.class)
  public void testTruncatedListEntry() {
    Tlvs.decodeList(new byte[] {0x01, 0x01, (byte) 0xAA, 0x02, 0x04, 0x01, 0x02});
  }
}

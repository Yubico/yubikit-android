/*
 * Copyright (C) 2019-2022 Yubico.
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

package com.yubico.yubikit.core.smartcard;

import java.util.Arrays;
import javax.annotation.Nullable;

/** Data model for encapsulating an APDU command, as defined by ISO/IEC 7816-4 standard. */
public class Apdu {
  private final byte cla;
  private final byte ins;
  private final byte p1;
  private final byte p2;
  private final byte[] data;
  private final int le;

  /**
   * Creates a new command APDU from a list of parameters specified by the ISO/IEC 7816-4 standard.
   *
   * @param cla the instruction class
   * @param ins the instruction number
   * @param p1 the first instruction parameter byte
   * @param p2 the second instruction parameter byte
   * @param data the command data
   * @param le the length of expected data in the response
   */
  private Apdu(byte cla, byte ins, byte p1, byte p2, @Nullable byte[] data, int le) {
    this.cla = cla;
    this.ins = ins;
    this.p1 = p1;
    this.p2 = p2;
    this.data = data == null ? new byte[0] : data;
    this.le = le;
  }

  private Apdu(byte cla, byte ins, byte p1, byte p2, @Nullable byte[] data) {
    this(cla, ins, p1, p2, data, 0);
  }

  /** Constructor using int's for convenience. See {@link #Apdu(byte, byte, byte, byte, byte[])}. */
  public Apdu(int cla, int ins, int p1, int p2, @Nullable byte[] data, int le) {
    this(
        validateByte(cla, "CLA"),
        validateByte(ins, "INS"),
        validateByte(p1, "P1"),
        validateByte(p2, "P2"),
        data,
        le);
  }

  public Apdu(int cla, int ins, int p1, int p2, @Nullable byte[] data) {
    this(cla, ins, p1, p2, data, 0);
  }

  /** Returns the data payload of the APDU. */
  public byte[] getData() {
    return Arrays.copyOf(data, data.length);
  }

  /** Returns the CLA of the APDU. */
  public byte getCla() {
    return cla;
  }

  /** Returns the INS of the APDU. */
  public byte getIns() {
    return ins;
  }

  /** Returns the parameter P1 of the APDU. */
  public byte getP1() {
    return p1;
  }

  /** Returns the parameter P2 of the APDU. */
  public byte getP2() {
    return p2;
  }

  public int getLe() {
    return le;
  }

  /*
   * Validates that integer passed fits into byte and converts to byte
   */
  private static byte validateByte(int byteInt, String name) {
    if (byteInt > 255 || byteInt < Byte.MIN_VALUE) {
      throw new IllegalArgumentException("Invalid value for " + name + ", must fit in a byte");
    }
    return (byte) byteInt;
  }
}

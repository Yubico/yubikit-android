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

package com.yubico.yubikit.android.transport.usb.connection;

import org.jspecify.annotations.Nullable;

/**
 * The seven-byte T=1 {@code abProtocolDataStructure} of {@code PC_to_RDR_SetParameters} (CCID 1.10
 * §6.3.6), derived from what the card announced in its ATR.
 *
 * <p>A TPDU-level reader does not act on the ATR's interface bytes for us, so unless we hand it
 * these it keeps whatever it defaulted to - which on an Identiv SCR3500 C means staying at the
 * default bus rate even though it advertises auto-PPS, turning a 12 KB read from ~1-2 s into ~16 s.
 *
 * <p>Fields the card left out of the ATR fall back to the ISO 7816-3 defaults rather than being
 * omitted: the structure is fixed-width, so every byte has to carry something.
 */
final class T1Parameters {

  /** bProtocolNum selecting T=1 in the SetParameters header (CCID 1.10 §6.3.6). */
  static final byte PROTOCOL_NUM_T1 = 0x01;

  /** Default Fi/Di when the ATR omits TA1 (ISO 7816-3 §8.3). */
  private static final byte DEFAULT_FINDEX_DINDEX = 0x11;

  /** bmTCCKST1: T=1, LRC checksum, direct convention - the only shape {@link T1Block} builds. */
  private static final byte TCCKST1_T1_LRC_DIRECT = 0x10;

  /** Default extra guard time when the ATR omits TC1 (ISO 7816-3 §8.3). */
  private static final byte DEFAULT_GUARD_TIME = 0x00;

  /** Default BWI=4, CWI=13 when the ATR omits TB3 (ISO 7816-3 §11.4.3). */
  private static final byte DEFAULT_WAITING_INTEGERS = 0x4D;

  /** bClockStop: stopping the clock is not allowed. */
  private static final byte CLOCK_STOP_NOT_ALLOWED = 0x00;

  /** Default IFSC of 32 bytes when the ATR omits TA3 (ISO 7816-3 §11.4.2). */
  private static final byte DEFAULT_IFSC = 0x20;

  private final byte findexDindex;
  private final byte guardTime;
  private final byte waitingIntegers;
  private final byte ifsc;

  private T1Parameters(byte findexDindex, byte guardTime, byte waitingIntegers, byte ifsc) {
    this.findexDindex = findexDindex;
    this.guardTime = guardTime;
    this.waitingIntegers = waitingIntegers;
    this.ifsc = ifsc;
  }

  /** Fi/Di as sent, for logging. */
  int findexDindex() {
    return findexDindex & 0xFF;
  }

  /** IFSC as sent, for logging. */
  int ifsc() {
    return ifsc & 0xFF;
  }

  /**
   * The structure in wire order: bmFindexDindex, bmTCCKST1, bGuardTimeT1, bWaitingIntegersT1,
   * bClockStop, bIFSC, bNadValue.
   */
  byte[] toBytes() {
    return new byte[] {
      findexDindex,
      TCCKST1_T1_LRC_DIRECT,
      guardTime,
      waitingIntegers,
      CLOCK_STOP_NOT_ALLOWED,
      ifsc,
      T1Block.NAD_DEFAULT
    };
  }

  /**
   * Take the four interface bytes this structure has a home for - TA1 (Fi/Di), TC1 (extra guard
   * time), TA3 (IFSC) and TB3 (BWI/CWI) - out of an ATR, defaulting whichever the card omitted.
   */
  static T1Parameters fromAtr(byte @Nullable [] atr) {
    AtrInterfaceBytes interfaceBytes = AtrInterfaceBytes.parse(atr);
    Byte ta1 = interfaceBytes.ta(1);
    Byte tc1 = interfaceBytes.tc(1);
    Byte tb3 = interfaceBytes.tb(3);
    Byte ta3 = interfaceBytes.ta(3);
    return new T1Parameters(
        ta1 != null ? ta1 : DEFAULT_FINDEX_DINDEX,
        tc1 != null ? tc1 : DEFAULT_GUARD_TIME,
        tb3 != null ? tb3 : DEFAULT_WAITING_INTEGERS,
        ta3 != null ? ta3 : DEFAULT_IFSC);
  }
}

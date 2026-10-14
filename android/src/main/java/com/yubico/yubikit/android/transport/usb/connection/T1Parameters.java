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

  /** Clocks per etu before any speed-up: Fi=372, Di=1 (ISO 7816-3 §8.3). */
  private static final int DEFAULT_ETU_CLOCKS = 372;

  /**
   * Fi by the upper nibble of TA1 (ISO 7816-3 Table 7). Reserved indexes read as the default, which
   * is what a card that sends one is held to.
   */
  private static final int[] FI_BY_INDEX = {
    372, 372, 558, 744, 1116, 1488, 1860, 372, 372, 512, 768, 1024, 1536, 2048, 372, 372,
  };

  /** BWI is only defined up to 9; anything above is reserved (ISO 7816-3 §11.4.3). */
  private static final int MAX_BWI = 9;

  /** Card clock assumed when the reader's descriptor does not give one: 3.57 MHz. */
  private static final long FALLBACK_CLOCK_KHZ = 3571;

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

  /** BWI, the upper nibble of TB3: the card's block waiting time exponent. */
  int bwi() {
    return (waitingIntegers >> 4) & 0x0F;
  }

  /**
   * How long the card may take to start answering a block, in milliseconds, at the slowest bus rate
   * the reader can be running.
   *
   * <p>BWT = 11 etu + 2^BWI x 960 etu (ISO 7816-3 §11.4.3). The length of an etu depends on a rate
   * the reader negotiates for itself, so this takes the slowest it could be using: Fi/Di=372/1, or
   * the card's own Fi if that is larger, with Di=1. A faster rate only shortens the real wait, so
   * the result is an upper bound and a timeout built on it never fires early.
   *
   * @param clockKhz the card clock, from the reader's {@code dwDefaultClock}; 0 if it gave none
   */
  long blockWaitingTimeMillis(long clockKhz) {
    int fi = FI_BY_INDEX[(findexDindex >> 4) & 0x0F];
    return blockWaitingTimeMillis(bwi(), Math.max(DEFAULT_ETU_CLOCKS, fi), clockKhz);
  }

  static long blockWaitingTimeMillis(int bwi, int etuClocks, long clockKhz) {
    long etus = 11 + (1L << Math.min(bwi, MAX_BWI)) * 960;
    long clock = clockKhz > 0 ? clockKhz : FALLBACK_CLOCK_KHZ;
    // clocks / (clock in kHz) is milliseconds, rounded up.
    return (etus * etuClocks + clock - 1) / clock;
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

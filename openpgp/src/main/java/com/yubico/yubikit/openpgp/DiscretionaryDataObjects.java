/*
 * Copyright (C) 2023 Yubico.
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

package com.yubico.yubikit.openpgp;

import com.yubico.yubikit.core.util.Tlvs;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.annotation.Nullable;

public class DiscretionaryDataObjects {
  private static final int TAG_EXTENDED_CAPABILITIES = 0xC0;
  private static final int TAG_FINGERPRINTS = 0xC5;
  private static final int TAG_CA_FINGERPRINTS = 0xC6;
  private static final int TAG_GENERATION_TIMES = 0xCD;
  private static final int TAG_KEY_INFORMATION = 0xDE;
  private final ExtendedCapabilities extendedCapabilities;

  private final AlgorithmAttributes attributesSig;
  private final AlgorithmAttributes attributesDec;
  private final AlgorithmAttributes attributesAut;
  @Nullable private final AlgorithmAttributes attributesAtt;
  private final PwStatus pwStatus;
  private final Map<KeyRef, byte[]> fingerprints;
  private final Map<KeyRef, byte[]> caFingerprints;
  private final Map<KeyRef, Integer> generationTimes;
  private final Map<KeyRef, KeyStatus> keyInformation;
  @Nullable private final Uif uifSig;
  @Nullable private final Uif uifDec;
  @Nullable private final Uif uifAut;
  @Nullable private final Uif uifAtt;

  public DiscretionaryDataObjects(
      ExtendedCapabilities extendedCapabilities,
      AlgorithmAttributes attributesSig,
      AlgorithmAttributes attributesDec,
      AlgorithmAttributes attributesAut,
      @Nullable AlgorithmAttributes attributesAtt,
      PwStatus pwStatus,
      Map<KeyRef, byte[]> fingerprints,
      Map<KeyRef, byte[]> caFingerprints,
      Map<KeyRef, Integer> generationTimes,
      Map<KeyRef, KeyStatus> keyInformation,
      @Nullable Uif uifSig,
      @Nullable Uif uifDec,
      @Nullable Uif uifAut,
      @Nullable Uif uifAtt) {
    this.extendedCapabilities = extendedCapabilities;
    this.attributesSig = attributesSig;
    this.attributesDec = attributesDec;
    this.attributesAut = attributesAut;
    this.attributesAtt = attributesAtt;
    this.pwStatus = pwStatus;
    this.fingerprints = fingerprints;
    this.caFingerprints = caFingerprints;
    this.generationTimes = generationTimes;
    this.keyInformation = keyInformation;
    this.uifSig = uifSig;
    this.uifDec = uifDec;
    this.uifAut = uifAut;
    this.uifAtt = uifAtt;
  }

  public ExtendedCapabilities getExtendedCapabilities() {
    return extendedCapabilities;
  }

  public PwStatus getPwStatus() {
    return pwStatus;
  }

  @Nullable
  public AlgorithmAttributes getAlgorithmAttributes(KeyRef keyRef) {
    switch (keyRef) {
      case SIG:
        return attributesSig;
      case DEC:
        return attributesDec;
      case AUT:
        return attributesAut;
      case ATT:
        return attributesAtt;
      default:
        throw new IllegalStateException();
    }
  }

  @Nullable
  public byte[] getFingerprint(KeyRef keyRef) {
    byte[] fingerprint = fingerprints.get(keyRef);
    if (fingerprint != null) {
      return Arrays.copyOf(fingerprint, fingerprint.length);
    }
    return null;
  }

  @Nullable
  public byte[] getCaFingerprint(KeyRef keyRef) {
    byte[] fingerprint = caFingerprints.get(keyRef);
    if (fingerprint != null) {
      return Arrays.copyOf(fingerprint, fingerprint.length);
    }
    return null;
  }

  public int getGenerationTime(KeyRef keyRef) {
    Integer time = generationTimes.get(keyRef);
    if (time != null) {
      return time;
    }
    return -1;
  }

  @Nullable
  public KeyStatus getKeyStatus(KeyRef keyRef) {
    return keyInformation.get(keyRef);
  }

  @Nullable
  public Uif getUif(KeyRef keyRef) {
    switch (keyRef) {
      case SIG:
        return uifSig;
      case DEC:
        return uifDec;
      case AUT:
        return uifAut;
      case ATT:
        return uifAtt;
      default:
        throw new IllegalStateException();
    }
  }

  private static Map<KeyRef, byte[]> parseFingerprints(byte[] encoded) {
    KeyRef[] refs = KeyRef.values();
    Map<KeyRef, byte[]> fingerprints = new HashMap<>();
    ByteBuffer buf = ByteBuffer.wrap(encoded);
    byte[] fingerprint = new byte[20];
    for (int i = 0; buf.remaining() > 0; i++) {
      buf.get(fingerprint);
      fingerprints.put(refs[i], fingerprint);
    }
    return fingerprints;
  }

  private static Map<KeyRef, Integer> parseTimestamps(byte[] encoded) {
    KeyRef[] refs = KeyRef.values();
    Map<KeyRef, Integer> timestamps = new HashMap<>();
    ByteBuffer buf = ByteBuffer.wrap(encoded);
    for (int i = 0; buf.remaining() > 0; i++) {
      timestamps.put(refs[i], buf.getInt());
    }
    return timestamps;
  }

  private static Map<KeyRef, KeyStatus> parseKeyInformation(byte[] encoded) {
    Map<KeyRef, KeyStatus> statuses = new HashMap<>();
    ByteBuffer buf = ByteBuffer.wrap(encoded);
    for (int i = 0; buf.remaining() > 0; i++) {
      statuses.put(KeyRef.fromValue(buf.get()), KeyStatus.fromValue(buf.get()));
    }
    return statuses;
  }

  static DiscretionaryDataObjects parse(byte[] encoded) {
    Map<Integer, byte[]> data = Tlvs.decodeMap(encoded);

    return new DiscretionaryDataObjects(
        ExtendedCapabilities.parse(data.get(TAG_EXTENDED_CAPABILITIES)),
        AlgorithmAttributes.parse(data.get(Do.ALGORITHM_ATTRIBUTES_SIG)),
        AlgorithmAttributes.parse(data.get(Do.ALGORITHM_ATTRIBUTES_DEC)),
        AlgorithmAttributes.parse(data.get(Do.ALGORITHM_ATTRIBUTES_AUT)),
        data.containsKey(Do.ALGORITHM_ATTRIBUTES_ATT)
            ? AlgorithmAttributes.parse(data.get(Do.ALGORITHM_ATTRIBUTES_ATT))
            : null,
        PwStatus.parse(data.get(Do.PW_STATUS_BYTES)),
        parseFingerprints(data.get(TAG_FINGERPRINTS)),
        parseFingerprints(data.get(TAG_CA_FINGERPRINTS)),
        parseTimestamps(data.get(TAG_GENERATION_TIMES)),
        parseKeyInformation(
            data.containsKey(TAG_KEY_INFORMATION) ? data.get(TAG_KEY_INFORMATION) : new byte[0]),
        data.containsKey(Do.UIF_SIG) ? Uif.fromValue(data.get(Do.UIF_SIG)[0]) : null,
        data.containsKey(Do.UIF_DEC) ? Uif.fromValue(data.get(Do.UIF_DEC)[0]) : null,
        data.containsKey(Do.UIF_AUT) ? Uif.fromValue(data.get(Do.UIF_AUT)[0]) : null,
        data.containsKey(Do.UIF_ATT) ? Uif.fromValue(data.get(Do.UIF_ATT)[0]) : null);
  }
}

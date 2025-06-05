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

package com.yubico.yubikit.fido.webauthn;

import com.yubico.yubikit.fido.Cbor;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.Map;
import java.util.Objects;
import javax.annotation.Nullable;

/**
 * Webauthn AuthenticatorData class
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data">WebAuthn
 *     Authenticator Data</a>
 */
public class AuthenticatorData {
  @SuppressWarnings("unused")
  public static final int FLAG_UP = 0x00;

  @SuppressWarnings("unused")
  public static final int FLAG_UV = 0x02;

  public static final int FLAG_AT = 0x06;
  public static final int FLAG_ED = 0x07;

  private final byte[] rpIdHash;
  private final byte flags;
  private final int signCount;

  @Nullable private final AttestedCredentialData attestedCredentialData;
  @Nullable private final Map<String, ?> extensions;

  private final byte[] rawData;

  private static boolean getFlag(byte flags, int bitIndex) {
    return (flags >> bitIndex & 1) == 1;
  }

  public AuthenticatorData(
      byte[] rpIdHash,
      byte flags,
      int signCount,
      @Nullable AttestedCredentialData attestedCredentialData,
      @Nullable Map<String, ?> extensions,
      byte[] rawData) {
    this.rpIdHash = rpIdHash;
    this.flags = flags;
    this.signCount = signCount;
    this.attestedCredentialData = attestedCredentialData;
    this.extensions = extensions;
    this.rawData = rawData;
  }

  @SuppressWarnings("unchecked")
  public static AuthenticatorData parseFrom(ByteBuffer buffer) {
    int startPos = buffer.position();
    final byte[] rpIdHash = new byte[32];
    buffer.get(rpIdHash);
    final byte flags = buffer.get();
    final int signCount = buffer.order(ByteOrder.BIG_ENDIAN).getInt();

    boolean flagAT = getFlag(flags, FLAG_AT);
    boolean flagED = getFlag(flags, FLAG_ED);

    AttestedCredentialData attestedCredentialData =
        flagAT ? AttestedCredentialData.parseFrom(buffer) : null;

    if (!flagED && buffer.hasRemaining()) {
      throw new IllegalArgumentException("Unexpected extensions data");
    }

    if (flagED && !buffer.hasRemaining()) {
      throw new IllegalArgumentException("Missing extensions data");
    }

    Map<String, ?> extensions = flagED ? (Map<String, ?>) Cbor.decodeFrom(buffer) : null;

    // there should not be anything more in the buffer at this point
    if (buffer.hasRemaining()) {
      throw new IllegalArgumentException("Unexpected data in authenticatorData");
    }

    byte[] originalData = new byte[buffer.position() - startPos];
    buffer.position(startPos);
    buffer.get(originalData);

    return new AuthenticatorData(
        rpIdHash, flags, signCount, attestedCredentialData, extensions, originalData);
  }

  @SuppressWarnings("unused")
  public byte[] getRpIdHash() {
    return rpIdHash;
  }

  @SuppressWarnings("unused")
  public byte getFlags() {
    return flags;
  }

  @SuppressWarnings("unused")
  public int getSignCount() {
    return signCount;
  }

  @Nullable
  @SuppressWarnings("unused")
  public AttestedCredentialData getAttestedCredentialData() {
    return attestedCredentialData;
  }

  @Nullable
  @SuppressWarnings("unused")
  public Map<String, ?> getExtensions() {
    return extensions;
  }

  @SuppressWarnings("unused")
  public boolean isUp() {
    return getFlag(flags, FLAG_UP);
  }

  @SuppressWarnings("unused")
  public boolean isUv() {
    return getFlag(flags, FLAG_UV);
  }

  @SuppressWarnings("unused")
  public boolean isAt() {
    return getFlag(flags, FLAG_AT);
  }

  @SuppressWarnings("unused")
  public boolean isEd() {
    return getFlag(flags, FLAG_ED);
  }

  @SuppressWarnings("unused")
  public byte[] getBytes() {
    return rawData;
  }

  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;

    AuthenticatorData that = (AuthenticatorData) o;

    if (flags != that.flags) return false;
    if (signCount != that.signCount) return false;
    if (!Arrays.equals(rpIdHash, that.rpIdHash)) return false;
    if (!Objects.equals(attestedCredentialData, that.attestedCredentialData)) {
      return false;
    }
    if (extensions != null && that.extensions != null) {
      if (!Arrays.equals(Cbor.encode(extensions), Cbor.encode(that.extensions))) return false;
    }

    if ((extensions != null && that.extensions == null)
        || (extensions == null && that.extensions != null)) {
      return false;
    }

    return Arrays.equals(rawData, that.rawData);
  }

  @Override
  public int hashCode() {
    int result = Arrays.hashCode(rpIdHash);
    result = 31 * result + (int) flags;
    result = 31 * result + signCount;
    result = 31 * result + (attestedCredentialData != null ? attestedCredentialData.hashCode() : 0);
    result = 31 * result + (extensions != null ? Arrays.hashCode(Cbor.encode(extensions)) : 0);
    result = 31 * result + Arrays.hashCode(rawData);
    return result;
  }
}

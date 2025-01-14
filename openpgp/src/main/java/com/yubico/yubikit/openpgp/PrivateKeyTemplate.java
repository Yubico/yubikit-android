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

import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.annotation.Nullable;
import javax.security.auth.Destroyable;

abstract class PrivateKeyTemplate implements Destroyable {
  private final byte[] crt;

  private boolean destroyed = false;

  PrivateKeyTemplate(byte[] crt) {
    this.crt = crt;
  }

  abstract List<Tlv> getTemplate();

  @Override
  public void destroy() {
    Arrays.fill(crt, (byte) 0);
    destroyed = true;
  }

  @Override
  public boolean isDestroyed() {
    return destroyed;
  }

  byte[] getBytes() {
    ByteBuffer headers = ByteBuffer.allocate(1024);
    ByteBuffer values = ByteBuffer.allocate(1024);
    for (Tlv tlv : getTemplate()) {
      byte[] tlvBytes = tlv.getBytes();
      headers.put(tlvBytes, 0, tlvBytes.length - tlv.getLength());
      values.put(tlv.getValue());
    }
    headers.flip();
    byte[] headersBytes = new byte[headers.remaining()];
    headers.get(headersBytes);

    values.flip();
    byte[] valuesBytes = new byte[values.remaining()];
    values.get(valuesBytes);

    byte[] tlvBytes =
        Tlvs.encodeList(Arrays.asList(new Tlv(0x7f48, headersBytes), new Tlv(0x5f48, valuesBytes)));

    return new Tlv(
            0x4d, ByteBuffer.allocate(crt.length + tlvBytes.length).put(crt).put(tlvBytes).array())
        .getBytes();
  }

  static class Rsa extends PrivateKeyTemplate {
    final byte[] e;
    final byte[] p;
    final byte[] q;

    Rsa(byte[] crt, byte[] e, byte[] p, byte[] q) {
      super(crt);
      this.e = e;
      this.p = p;
      this.q = q;
    }

    @Override
    List<Tlv> getTemplate() {
      return Arrays.asList(new Tlv(0x91, e), new Tlv(0x92, p), new Tlv(0x93, q));
    }

    @Override
    public void destroy() {
      Arrays.fill(e, (byte) 0);
      Arrays.fill(p, (byte) 0);
      Arrays.fill(q, (byte) 0);
      super.destroy();
    }
  }

  static class RsaCrt extends Rsa {
    final byte[] iqmp;
    final byte[] dmp1;
    final byte[] dmq1;
    final byte[] n;

    RsaCrt(
        byte[] crt, byte[] e, byte[] p, byte[] q, byte[] iqmp, byte[] dmp1, byte[] dmq1, byte[] n) {
      super(crt, e, p, q);
      this.iqmp = iqmp;
      this.dmp1 = dmp1;
      this.dmq1 = dmq1;
      this.n = n;
    }

    @Override
    List<Tlv> getTemplate() {
      List<Tlv> tlvs = new ArrayList<>(super.getTemplate());
      tlvs.addAll(
          Arrays.asList(
              new Tlv(0x94, iqmp), new Tlv(0x95, dmp1), new Tlv(0x96, dmq1), new Tlv(0x97, n)));

      return tlvs;
    }

    @Override
    public void destroy() {
      Arrays.fill(iqmp, (byte) 0);
      Arrays.fill(dmp1, (byte) 0);
      Arrays.fill(dmq1, (byte) 0);
      Arrays.fill(n, (byte) 0);
      super.destroy();
    }
  }

  static class Ec extends PrivateKeyTemplate {
    final byte[] privateKey;
    @Nullable final byte[] publicKey;

    Ec(byte[] crt, byte[] privateKey, @Nullable byte[] publicKey) {
      super(crt);
      this.privateKey = privateKey;
      this.publicKey = publicKey;
    }

    @Override
    List<Tlv> getTemplate() {
      List<Tlv> tlvs = new ArrayList<>();
      tlvs.add(new Tlv(0x92, privateKey));
      if (publicKey != null) {
        tlvs.add(new Tlv(0x99, publicKey));
      }
      return tlvs;
    }

    @Override
    public void destroy() {
      Arrays.fill(privateKey, (byte) 0);
      if (publicKey != null) {
        Arrays.fill(publicKey, (byte) 0);
      }
      super.destroy();
    }
  }
}

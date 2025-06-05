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

package com.yubico.yubikit.core.keys;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;
import javax.security.auth.DestroyFailedException;
import javax.security.auth.Destroyable;

/**
 * Contains private key values to be imported into a YubiKey.
 *
 * <p>Can be created from a {@link PrivateKey} by using {@link #fromPrivateKey(PrivateKey)}.
 *
 * <p>Once used, clear the secret keying material by calling {@link #destroy()}.
 */
public abstract class PrivateKeyValues implements Destroyable {
  private static final byte[] OID_ECDSA =
      new byte[] {0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01};
  final int bitLength;
  private boolean destroyed = false;

  protected PrivateKeyValues(int bitLength) {
    this.bitLength = bitLength;
  }

  public final int getBitLength() {
    return bitLength;
  }

  @Override
  public final boolean isDestroyed() {
    return destroyed;
  }

  @Override
  public void destroy() throws DestroyFailedException {
    destroyed = true;
  }

  /**
   * Constructs a PrivateKeyValues instance using values from a JCA {@link PrivateKey}.
   *
   * @param privateKey the private key to extract values from
   * @return private key values
   */
  public static PrivateKeyValues fromPrivateKey(PrivateKey privateKey) {
    if (privateKey instanceof RSAPrivateKey) {
      return Rsa.fromRsaPrivateKey((RSAPrivateKey) privateKey);
    } else {
      byte[] encoded = privateKey.getEncoded();
      try {
        Map<Integer, byte[]> tlvs = Tlvs.decodeMap(Tlvs.unpackValue(0x30, encoded));
        List<Tlv> sequence = Tlvs.decodeList(tlvs.get(0x30));
        byte[] algorithm = sequence.get(0).getValue();
        if (Arrays.equals(OID_ECDSA, algorithm)) {
          byte[] parameter = sequence.get(1).getValue();
          EllipticCurveValues curve = EllipticCurveValues.fromOid(parameter);
          sequence = Tlvs.decodeList(Tlvs.unpackValue(0x30, tlvs.get(0x04)));
          return new Ec(curve, sequence.get(1).getValue());
        } else {
          for (EllipticCurveValues curve :
              Arrays.asList(EllipticCurveValues.Ed25519, EllipticCurveValues.X25519)) {
            if (Arrays.equals(curve.getOid(), algorithm)) {
              return new Ec(curve, Tlvs.unpackValue(0x04, tlvs.get(0x04)));
            }
          }
        }
      } catch (BadResponseException e) {
        // ignore, fall through to exception
      }
    }

    throw new IllegalArgumentException("Unsupported private key type");
  }

  public static class Ec extends PrivateKeyValues {
    private final EllipticCurveValues ellipticCurveValues;
    private final byte[] secret;

    protected Ec(EllipticCurveValues ellipticCurveValues, byte[] secret) {
      super(ellipticCurveValues.getBitLength());
      this.ellipticCurveValues = ellipticCurveValues;
      this.secret = Arrays.copyOf(secret, secret.length);
    }

    public EllipticCurveValues getCurveParams() {
      return ellipticCurveValues;
    }

    public byte[] getSecret() {
      return Arrays.copyOf(secret, secret.length);
    }

    @Override
    public void destroy() throws DestroyFailedException {
      Arrays.fill(secret, (byte) 0);
      super.destroy();
    }

    @Override
    public String toString() {
      return "PrivateKeyValues.Ec{"
          + "curve="
          + ellipticCurveValues.name()
          + ", bitLength="
          + bitLength
          + ", destroyed="
          + isDestroyed()
          + '}';
    }
  }

  public static class Rsa extends PrivateKeyValues {
    private final BigInteger modulus;
    private final BigInteger publicExponent;
    private BigInteger primeP;
    private BigInteger primeQ;
    @Nullable private BigInteger primeExponentP;
    @Nullable private BigInteger primeExponentQ;
    @Nullable private BigInteger crtCoefficient;

    @Override
    public String toString() {
      boolean hasCrt = crtCoefficient != null;
      return "PrivateKeyValues.Rsa{"
          + "modulus="
          + modulus
          + ", publicExponent="
          + publicExponent
          + ", bitLength="
          + bitLength
          + ", hasCrtValues="
          + hasCrt
          + ", destroyed="
          + isDestroyed()
          + '}';
    }

    protected Rsa(
        BigInteger modulus,
        BigInteger publicExponent,
        BigInteger primeP,
        BigInteger primeQ,
        @Nullable BigInteger primeExponentP,
        @Nullable BigInteger primeExponentQ,
        @Nullable BigInteger crtCoefficient) {
      super(modulus.bitLength());
      this.modulus = modulus;
      this.publicExponent = publicExponent;
      this.primeP = primeP;
      this.primeQ = primeQ;
      this.primeExponentP = primeExponentP;
      this.primeExponentQ = primeExponentQ;
      this.crtCoefficient = crtCoefficient;

      if (!((primeExponentP != null && primeExponentQ != null && crtCoefficient != null)
          || (primeExponentP == null && primeExponentQ == null && crtCoefficient == null))) {
        throw new IllegalArgumentException("All CRT values must either be present or omitted");
      }
    }

    public BigInteger getModulus() {
      return modulus;
    }

    public BigInteger getPublicExponent() {
      return publicExponent;
    }

    public BigInteger getPrimeP() {
      return primeP;
    }

    public BigInteger getPrimeQ() {
      return primeQ;
    }

    @Nullable
    public BigInteger getPrimeExponentP() {
      return primeExponentP;
    }

    @Nullable
    public BigInteger getPrimeExponentQ() {
      return primeExponentQ;
    }

    @Nullable
    public BigInteger getCrtCoefficient() {
      return crtCoefficient;
    }

    @Override
    public void destroy() throws DestroyFailedException {
      primeP = BigInteger.ZERO;
      primeQ = BigInteger.ZERO;
      primeExponentP = null;
      primeExponentQ = null;
      crtCoefficient = null;
      super.destroy();
    }

    private static Rsa fromRsaPrivateKey(RSAPrivateKey key) {
      List<BigInteger> values;
      if (key instanceof RSAPrivateCrtKey) {
        RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) key;
        values =
            Arrays.asList(
                rsaPrivateKey.getModulus(),
                rsaPrivateKey.getPublicExponent(),
                rsaPrivateKey.getPrivateExponent(),
                rsaPrivateKey.getPrimeP(),
                rsaPrivateKey.getPrimeQ(),
                rsaPrivateKey.getPrimeExponentP(),
                rsaPrivateKey.getPrimeExponentQ(),
                rsaPrivateKey.getCrtCoefficient());
      } else if ("PKCS#8".equals(key.getFormat())) {
        values = parsePkcs8RsaKeyValues(key.getEncoded());
      } else {
        throw new IllegalArgumentException("Unsupported private key encoding");
      }
      if (values.get(1).intValue() != 65537) {
        throw new IllegalArgumentException("Unsupported RSA public exponent");
      }

      return new Rsa(
          values.get(0), // n
          values.get(1), // e
          values.get(3), // p
          values.get(4), // q
          values.get(5), // dmp1
          values.get(6), // dmq1
          values.get(7) // iqmp
          );
    }

    /*
    Parse a DER encoded PKCS#8 RSA key
     */
    static List<BigInteger> parsePkcs8RsaKeyValues(byte[] derKey) {
      try {
        List<Tlv> numbers =
            Tlvs.decodeList(
                Tlvs.decodeMap(Tlvs.decodeMap(Tlvs.unpackValue(0x30, derKey)).get(0x04)).get(0x30));
        List<BigInteger> values = new ArrayList<>();
        for (Tlv number : numbers) {
          values.add(new BigInteger(number.getValue()));
        }
        BigInteger first = values.remove(0);
        if (first.intValue() != 0) {
          throw new IllegalArgumentException("Expected value 0");
        }
        return values;
      } catch (BadResponseException e) {
        throw new IllegalArgumentException(e.getMessage());
      }
    }
  }
}

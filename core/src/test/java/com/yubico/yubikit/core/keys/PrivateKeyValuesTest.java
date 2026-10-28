/*
 * Copyright (C) 2023,2026 Yubico.
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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertThrows;

import com.yubico.yubikit.Codec;
import com.yubico.yubikit.core.internal.codec.Base64;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;
import java.security.PrivateKey;
import java.util.Arrays;
import java.util.List;
import javax.security.auth.DestroyFailedException;
import org.junit.Test;

@SuppressWarnings("SpellCheckingInspection")
public class PrivateKeyValuesTest {
  private static final String MLDSA_65_SEED_HEX =
      "0d5495f59f72a7ec22f5df33bf8f835e31c4c69942034fbd689bf9cb495f845d";

  @Test
  public void testParsePkcs8RsaKeyValues() {
    PrivateKeyValues.Rsa.parsePkcs8RsaKeyValues(
        Base64.fromUrlSafeString(
            "MIICdQIBADANBgkqhkiG9w0BAQEFAASCAl8wggJbAgEAAoGBALWeZ0E5O2l_iHfck9mokf1iWH2eZDWQoJoQK"
                + "UOAeVoKUecNp250J5tL3EHONqWoF6VLO-B-6jTET4Iz97BeUj7gOJHmEw-nqFfguTVmNeeiZ711TNYN"
                + "pF7kwW7yWghWG-Q7iQEoMXfY3x4BL33H2gKRWtMHK66GJViL1l9s3qDXAgMBAAECgYBO753pFzrfS3L"
                + "Axbns6_snqcrULjdXoJhs3YFRuVEE9V9LkP-oXguoz3vXjgzqSvib-ur3U7HvZTM5X-TTXutXdQ5CyO"
                + "RLLtXEZcyCKQI9ihH5fSNJRWRbJ3xe-xi5NANRkRDkro7tm4a5ZD4PYvO4r29yVB5PXlMkOTLoxNSww"
                + "QJBAN5lW93Agi9Ge5B2-B2EnKSlUvj0-jJBkHYAFTiHyTZVEj6baeHBvJklhVczpWvTXb6Nr8cjAKVs"
                + "hFbdQoBwHmkCQQDRD7djZGIWH1Lz0rkL01nDj4z4QYMgUs3AQhnrXPBjEgNzphtJ2u7QrCSOBQQHlmA"
                + "PBDJ_MTxFJMzDIJGDA10_AkATJjEZz_ilr3D2SHgmuoNuXdneG-HrL-ALeQhavL5jkkGm6GTejnr5yN"
                + "RJZOYKecGppbOL9wSYOdbPT-_o9T55AkATXCY6cRBYRhxTcf8q5i6Y2pFOaBqxgpmFJVnrHtcwBXoGW"
                + "qqKQ1j8QAS-lh5SaY2JtnTKrI-NQ6Qmqbxv6n7XAkBkhLO7pplInVh2WjqXOV4ZAoOAAJlfpG5-z6mW"
                + "zCZ9-286OJQLr6OVVQMcYExUO9yVocZQX-4XqEIF0qAB7m31"));
  }

  @Test
  public void testParsePkcs8MlDsa() throws DestroyFailedException {
    for (MlDsaParameterValues params : MlDsaParameterValues.values()) {
      byte[] seed = sequence(params.getSeedLength());
      for (byte[] field : seedEncodings(seed, params.getExpandedPrivateKeyLength())) {
        PrivateKeyValues.MlDsa mlDsa =
            (PrivateKeyValues.MlDsa)
                PrivateKeyValues.fromPrivateKey(new StubPrivateKey(pkcs8(params.getOid(), field)));
        assertThat(mlDsa.getParameterValues(), equalTo(params));
        assertArrayEquals(seed, mlDsa.getSeed());
        mlDsa.destroy();
        assertThat(mlDsa.isDestroyed(), is(true));
        assertArrayEquals(new byte[seed.length], mlDsa.getSeed());
      }
    }
  }

  @Test
  public void testParsePkcs8MlKem() throws DestroyFailedException {
    for (MlKemParameterValues params : MlKemParameterValues.values()) {
      byte[] seed = sequence(params.getSeedLength());
      for (byte[] field : seedEncodings(seed, params.getExpandedPrivateKeyLength())) {
        PrivateKeyValues.MlKem mlKem =
            (PrivateKeyValues.MlKem)
                PrivateKeyValues.fromPrivateKey(new StubPrivateKey(pkcs8(params.getOid(), field)));
        assertThat(mlKem.getParameterValues(), equalTo(params));
        assertArrayEquals(seed, mlKem.getSeed());
        mlKem.destroy();
        assertThat(mlKem.isDestroyed(), is(true));
        assertArrayEquals(new byte[seed.length], mlKem.getSeed());
      }
    }
  }

  @Test
  public void testParsePkcs8MlDsaKeepsTheSeedOfTheFirstElement() {
    // The expanded key structure repeats tag 0x04 after the seed; the first element must win.
    byte[] seed = Codec.fromHex(MLDSA_65_SEED_HEX);
    byte[] expanded = new byte[MlDsaParameterValues.MLDSA_65.getExpandedPrivateKeyLength()];
    Arrays.fill(expanded, (byte) 0x04);
    PrivateKeyValues.MlDsa mlDsa =
        (PrivateKeyValues.MlDsa)
            PrivateKeyValues.fromPrivateKey(
                new StubPrivateKey(
                    pkcs8(
                        MlDsaParameterValues.MLDSA_65.getOid(), seedAndExpanded(seed, expanded))));
    assertArrayEquals(seed, mlDsa.getSeed());
  }

  @Test
  public void testParsePkcs8PqcRejectsEncodingsWithoutTheSeed() {
    MlDsaParameterValues params = MlDsaParameterValues.MLDSA_65;
    byte[] seed = sequence(params.getSeedLength());
    byte[] expanded = new byte[params.getExpandedPrivateKeyLength()];

    List<byte[]> invalid =
        Arrays.asList(
            // the expanded key alone, which does not hold the seed
            new Tlv(0x04, expanded).getBytes(),
            // seed of the wrong length
            new Tlv(0x80, sequence(params.getSeedLength() - 1)).getBytes(),
            new Tlv(0x04, sequence(params.getSeedLength() + 1)).getBytes(),
            // expanded key of the wrong length
            seedAndExpanded(seed, new byte[expanded.length - 1]),
            // elements in the wrong order
            Tlvs.encodeList(Arrays.asList(new Tlv(0x04, expanded), new Tlv(0x04, seed))),
            // an element too many
            new Tlv(
                    0x30,
                    Tlvs.encodeList(
                        Arrays.asList(
                            new Tlv(0x04, seed),
                            new Tlv(0x04, expanded),
                            new Tlv(0x04, new byte[1]))))
                .getBytes(),
            // data after the encoding
            concat(new Tlv(0x04, seed).getBytes(), new byte[] {0}),
            // an unknown choice
            new Tlv(0x81, seed).getBytes(),
            new byte[0]);

    for (byte[] field : invalid) {
      assertThrows(
          IllegalArgumentException.class,
          () -> PrivateKeyValues.fromPrivateKey(new StubPrivateKey(pkcs8(params.getOid(), field))));
    }
  }

  /** The encodings of a seed in the privateKey field which are accepted. */
  private static List<byte[]> seedEncodings(byte[] seed, int expandedLength) {
    byte[] expanded = new byte[expandedLength];
    return Arrays.asList(
        // implicit context specific OCTET STRING
        new Tlv(0x80, seed).getBytes(),
        // OCTET STRING
        new Tlv(0x04, seed).getBytes(),
        // seed and expanded key
        seedAndExpanded(seed, expanded),
        // seed and expanded key, in a further OCTET STRING
        new Tlv(0x04, seedAndExpanded(seed, expanded)).getBytes());
  }

  private static byte[] seedAndExpanded(byte[] seed, byte[] expanded) {
    return new Tlv(
            0x30, Tlvs.encodeList(Arrays.asList(new Tlv(0x04, seed), new Tlv(0x04, expanded))))
        .getBytes();
  }

  private static byte[] sequence(int length) {
    byte[] data = new byte[length];
    for (int i = 0; i < length; i++) {
      data[i] = (byte) (i + 1);
    }
    return data;
  }

  private static byte[] concat(byte[] first, byte[] second) {
    byte[] result = Arrays.copyOf(first, first.length + second.length);
    System.arraycopy(second, 0, result, first.length, second.length);
    return result;
  }

  private static byte[] pkcs8(byte[] algorithmOid, byte[] privateKeyField) {
    return new Tlv(
            0x30,
            Tlvs.encodeList(
                Arrays.asList(
                    new Tlv(0x02, new byte[] {0}),
                    new Tlv(0x30, new Tlv(0x06, algorithmOid).getBytes()),
                    new Tlv(0x04, privateKeyField))))
        .getBytes();
  }

  private static class StubPrivateKey implements PrivateKey {
    private final byte[] encoded;

    StubPrivateKey(byte[] encoded) {
      this.encoded = encoded.clone();
    }

    @Override
    public String getAlgorithm() {
      return "ML-DSA";
    }

    @Override
    public String getFormat() {
      return "PKCS#8";
    }

    @Override
    public byte[] getEncoded() {
      return encoded.clone();
    }
  }
}

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

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.MatcherAssert.assertThat;

import com.yubico.yubikit.testing.Codec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import org.junit.Test;

public class PublicKeyValuesTest {
  @Test
  public void testDecodeP256Key() throws InvalidKeySpecException, NoSuchAlgorithmException {
    @SuppressWarnings("SpellCheckingInspection")
    byte[] encoded =
        Codec.fromHex(
            "046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE"
                + "7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    ECPublicKey key =
        PublicKeyValues.Ec.fromEncodedPoint(EllipticCurveValues.SECP256R1, encoded).toPublicKey();
    assertThat(key.getAlgorithm(), equalTo("EC"));
    assertThat(key.getParams().getCurve().getField().getFieldSize(), equalTo(256));
  }

  @Test
  public void testDecodeP384Key() throws InvalidKeySpecException, NoSuchAlgorithmException {
    @SuppressWarnings("SpellCheckingInspection")
    byte[] encoded =
        Codec.fromHex(
            "0408D999057BA3D2D969260045C55B97F089025959A6F434D651D207D19FB96E9E4FE0E86EBE0E64F85B9"
                + "6A9C75295DF618E80F1FA5B1B3CEDB7BFE8DFFD6DBA74B275D875BC6CC43E904E505F256AB4255F"
                + "FD43E94D39E22D61501E700A940E80");
    ECPublicKey key =
        PublicKeyValues.Ec.fromEncodedPoint(EllipticCurveValues.SECP384R1, encoded).toPublicKey();
    assertThat(key.getAlgorithm(), equalTo("EC"));
    assertThat(key.getParams().getCurve().getField().getFieldSize(), equalTo(384));
  }

  @Test
  public void testDecodeRsa1024() throws InvalidKeySpecException, NoSuchAlgorithmException {
    @SuppressWarnings("SpellCheckingInspection")
    BigInteger modulus =
        new BigInteger(
            Codec.fromHex(
                "00C061DB5C051CE961F42898068E084D81EAB3245A6884CF8F8B379587E81C87A96CD4DC83FED14DB"
                    + "5EB6AC60B173797F6692B93AC285CDBD4F91F4968E65CDA579F82D2071ADFFE85F5FF424E8D"
                    + "9A33BFAC1B56C0975BC5B15710F475D45923880575F15B326314251C4DA5C9640EF240F3EF4"
                    + "9E61398F700449F16C6F06D532D"));
    BigInteger exponent = BigInteger.valueOf(65537);
    RSAPublicKey key = new PublicKeyValues.Rsa(modulus, exponent).toPublicKey();
    assertThat(key.getAlgorithm(), equalTo("RSA"));
    assertThat(key.getModulus(), equalTo(modulus));
    assertThat(key.getPublicExponent(), equalTo(exponent));
    assertThat(key.getModulus().bitLength(), equalTo(1024));
  }

  @Test
  public void testDecodeRsa2048() throws InvalidKeySpecException, NoSuchAlgorithmException {
    @SuppressWarnings("SpellCheckingInspection")
    BigInteger modulus =
        new BigInteger(
            Codec.fromHex(
                "00C6FC5B4D5C28B9CDD9047C5481B1F6A6A66683E3B9566E91CBBC9E852EAD96796C914A92315C1B4"
                    + "08045270D3C672FC7DA97F2258DBDE0681BD4E5D1112EEBB75AACDC712E62FCD4391513AE86"
                    + "7C0E3C70B77032FBBEF774AADE544C6D76B0D296FEC3A5E2BF8ED7BFD3A0F9E48CA60F4CD36"
                    + "162DC3AEE6A0CC47E6BA92704E88E6A110622B3E9FC0C7CAA083A9D93BEB2902F16D0626175"
                    + "1E5FA5B8F65E56A6C37B4EA27704AC2FCC7309211022ECFF04BF874A33ACB905699A40A617A"
                    + "F95EDE3308B3B438BFA888B5E82E3CFA7D403E2D32A7B554736ED947FC245943B656B189303"
                    + "2B82F82B6CAFB65BC491AFC645CD676B776F61A0B99FCB990606DA43E5"));
    BigInteger exponent = BigInteger.valueOf(65537);
    RSAPublicKey key = new PublicKeyValues.Rsa(modulus, exponent).toPublicKey();
    assertThat(key.getAlgorithm(), equalTo("RSA"));
    assertThat(key.getModulus(), equalTo(modulus));
    assertThat(key.getPublicExponent(), equalTo(exponent));
    assertThat(key.getModulus().bitLength(), equalTo(2048));
  }
}

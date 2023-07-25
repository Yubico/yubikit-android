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

package com.yubico.yubikit.core.internal;

import com.yubico.yubikit.core.application.BadResponseException;
import com.yubico.yubikit.core.util.Tlv;
import com.yubico.yubikit.core.util.Tlvs;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Used internally in YubiKit, don't use from applications.
 */
public final class PrivateKeyUtils {
    public static RsaPrivateNumbers getPrivateNumbers(PrivateKey key) throws UnsupportedEncodingException {
        List<BigInteger> values;
        if (key instanceof RSAPrivateCrtKey) {
            RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey) key;
            values = Arrays.asList(
                    rsaPrivateKey.getModulus(),
                    rsaPrivateKey.getPublicExponent(),
                    rsaPrivateKey.getPrivateExponent(),
                    rsaPrivateKey.getPrimeP(),
                    rsaPrivateKey.getPrimeQ(),
                    rsaPrivateKey.getPrimeExponentP(),
                    rsaPrivateKey.getPrimeExponentQ(),
                    rsaPrivateKey.getCrtCoefficient()
            );
        } else if ("PKCS#8".equals(key.getFormat())) {
            values = parsePkcs8RsaKeyValues(key.getEncoded());
        } else {
            throw new UnsupportedEncodingException("Unsupported private key encoding");
        }
        if (values.get(1).intValue() != 65537) {
            throw new UnsupportedEncodingException("Unsupported RSA public exponent");
        }

        int byteLength = values.get(0).bitLength() / 8;
        return new RsaPrivateNumbers(
                bytesToLength(values.get(0), byteLength), // n
                new byte[]{0x01, 0x00, 0x01},  // e = 65537
                bytesToLength(values.get(3), byteLength / 2), // p
                bytesToLength(values.get(4), byteLength / 2), // q
                bytesToLength(values.get(5), byteLength / 2), // dmp1
                bytesToLength(values.get(6), byteLength / 2), // dmq1
                bytesToLength(values.get(7), byteLength / 2)  // iqmp
        );
    }

    /*
     * Shortens to length or left-pads with 0.
     */
    public static byte[] bytesToLength(BigInteger value, int length) {
        byte[] data = value.toByteArray();
        if (data.length == length) {
            return data;
        } else if (data.length > length) {
            return Arrays.copyOfRange(data, data.length - length, data.length);
        } else {
            byte[] padded = new byte[length];
            System.arraycopy(data, 0, padded, length - data.length, data.length);
            return padded;
        }
    }

    /*
    Parse a DER encoded PKCS#8 RSA key
     */
    private static List<BigInteger> parsePkcs8RsaKeyValues(byte[] derKey) throws UnsupportedEncodingException {
        try {
            List<Tlv> numbers = Tlvs.decodeList(
                    Tlvs.decodeMap(
                            Tlvs.decodeMap(
                                    Tlvs.unpackValue(0x30, derKey)
                            ).get(0x04)
                    ).get(0x30)
            );
            List<BigInteger> values = new ArrayList<>();
            for (Tlv number : numbers) {
                values.add(new BigInteger(number.getValue()));
            }
            BigInteger first = values.remove(0);
            if (first.intValue() != 0) {
                throw new UnsupportedEncodingException("Expected value 0");
            }
            return values;
        } catch (BadResponseException e) {
            throw new UnsupportedEncodingException(e.getMessage());
        }
    }
}

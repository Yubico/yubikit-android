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

package com.yubico.yubikit.testing.sd;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assume.assumeFalse;

import com.yubico.yubikit.core.smartcard.scp.KeyRef;
import com.yubico.yubikit.core.smartcard.scp.Scp03KeyParams;
import com.yubico.yubikit.core.smartcard.scp.SecurityDomainSession;
import com.yubico.yubikit.core.smartcard.scp.StaticKeys;

import java.util.Map;

public class Scp03DeviceTests {

    static final KeyRef DEFAULT_KEY = new KeyRef((byte) 0x01, (byte) 0xff);

    public static void testImportKey(SecurityDomainTestState state) throws Throwable {

        final byte[] sk = new byte[]{
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        };
        final StaticKeys staticKeys = new StaticKeys(sk, sk, sk);
        final KeyRef newKey = new KeyRef((byte) 0x01, (byte) 0x01);

        assumeFalse("SCP03 not supported over NFC on FIPS capable devices",
                state.getDeviceInfo().getFipsCapable() != 0 && !state.isUsbTransport());

        state.withSecurityDomain(SecurityDomainSession::reset);
        state.withSecurityDomain(sd -> {
            sd.authenticate(new Scp03KeyParams(DEFAULT_KEY, StaticKeys.getDefaultKeys()));
            sd.putKey(newKey, staticKeys, 0);
        });

        state.withSecurityDomain(sd -> {
            Map<KeyRef, Map<Byte, Byte>> keyInformation = sd.getKeyInformation();
            // verify there are three SCP03 keys with kvn 0x01
            assertNotNull(keyInformation.get(scp03EncOf(newKey)));
            assertNotNull(keyInformation.get(scp03MacOf(newKey)));
            assertNotNull(keyInformation.get(scp03DekOf(newKey)));

            // the default keys are gone
            assertNull(keyInformation.get(scp03EncOf(DEFAULT_KEY)));
            assertNull(keyInformation.get(scp03MacOf(DEFAULT_KEY)));
            assertNull(keyInformation.get(scp03DekOf(DEFAULT_KEY)));
        });
    }

    public static void testDeleteKey(SecurityDomainTestState state) throws Throwable {

        final byte[] bytes1 = new byte[]{
                0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x67,
                0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x67,
        };
        final StaticKeys staticKeys1 = new StaticKeys(bytes1, bytes1, bytes1);

        final byte[] bytes2 = new byte[]{
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        };
        final StaticKeys staticKeys2 = new StaticKeys(bytes2, bytes2, bytes2);

        final KeyRef keyRef1 = new KeyRef((byte) 0x01, (byte) 0x10);
        final KeyRef keyRef2 = new KeyRef((byte) 0x01, (byte) 0x55);

        assumeFalse("SCP03 not supported over NFC on FIPS capable devices",
                state.getDeviceInfo().getFipsCapable() != 0 && !state.isUsbTransport());

        state.withSecurityDomain(SecurityDomainSession::reset);
        state.withSecurityDomain(sd -> {
            sd.authenticate(new Scp03KeyParams(DEFAULT_KEY, StaticKeys.getDefaultKeys()));
            sd.putKey(keyRef1, staticKeys1, 0);
        });

        // authenticate with the new key and put the second
        state.withSecurityDomain(sd -> {
            sd.authenticate(new Scp03KeyParams(keyRef1, staticKeys1));
            sd.putKey(keyRef2, staticKeys2, 0);

            // there are 2 SCP03 keys
            Map<KeyRef, Map<Byte, Byte>> keyInformation = sd.getKeyInformation();
            // verify there are three SCP03 keys with kvn 0x01
            assertNotNull(keyInformation.get(scp03EncOf(keyRef1)));
            assertNotNull(keyInformation.get(scp03MacOf(keyRef1)));
            assertNotNull(keyInformation.get(scp03DekOf(keyRef1)));

            assertNotNull(keyInformation.get(scp03EncOf(keyRef2)));
            assertNotNull(keyInformation.get(scp03MacOf(keyRef2)));
            assertNotNull(keyInformation.get(scp03DekOf(keyRef2)));
        });

        // delete first key
        state.withSecurityDomain(sd -> {
            // authenticate with the second key
            sd.authenticate(new Scp03KeyParams(keyRef2, staticKeys2));
            sd.deleteKey(keyRef1, false);

            // verify there are three the first key is deleted
            final Map<KeyRef, Map<Byte, Byte>> keyInformation = sd.getKeyInformation();
            assertNull(keyInformation.get(scp03EncOf(keyRef1)));
            assertNull(keyInformation.get(scp03MacOf(keyRef1)));
            assertNull(keyInformation.get(scp03DekOf(keyRef1)));

            assertNotNull(keyInformation.get(scp03EncOf(keyRef2)));
            assertNotNull(keyInformation.get(scp03MacOf(keyRef2)));
            assertNotNull(keyInformation.get(scp03DekOf(keyRef2)));
        });

        // delete the second key
        state.withSecurityDomain(sd -> {
            // authenticate with the second key
            sd.authenticate(new Scp03KeyParams(keyRef2, staticKeys2));
            sd.deleteKey(keyRef2, true); // the last key

            // verify that the second key is gone
            final Map<KeyRef, Map<Byte, Byte>> keyInformation = sd.getKeyInformation();
            assertNull(keyInformation.get(scp03EncOf(keyRef2)));
            assertNull(keyInformation.get(scp03MacOf(keyRef2)));
            assertNull(keyInformation.get(scp03DekOf(keyRef2)));

            // there now should be a default SCP03 key
            // it might be missing at all if the YubiKey supports other SCP versions
            for (KeyRef keyRef : keyInformation.keySet()) {
                final byte kid = keyRef.getKid();
                if (kid == (byte) 0x01 || kid == (byte) 0x02 || kid == (byte) 0x03) {
                    assertEquals(DEFAULT_KEY.getKvn(), keyRef.getKvn());
                }
            }
        });
    }

    public static void testReplaceKey(SecurityDomainTestState state) throws Throwable {

        final byte[] bytes1 = new byte[]{
                0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x67,
                0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x67,
        };
        final StaticKeys staticKeys1 = new StaticKeys(bytes1, bytes1, bytes1);

        final byte[] bytes2 = new byte[]{
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        };
        final StaticKeys staticKeys2 = new StaticKeys(bytes2, bytes2, bytes2);

        final KeyRef keyRef1 = new KeyRef((byte) 0x01, (byte) 0x10);
        final KeyRef keyRef2 = new KeyRef((byte) 0x01, (byte) 0x55);

        assumeFalse("SCP03 not supported over NFC on FIPS capable devices",
                state.getDeviceInfo().getFipsCapable() != 0 && !state.isUsbTransport());

        state.withSecurityDomain(SecurityDomainSession::reset);
        state.withSecurityDomain(sd -> {
            sd.authenticate(new Scp03KeyParams(DEFAULT_KEY, StaticKeys.getDefaultKeys()));
            sd.putKey(keyRef1, staticKeys1, 0);
        });

        // authenticate with the new key and replace it with the second
        state.withSecurityDomain(sd -> {
            sd.authenticate(new Scp03KeyParams(keyRef1, staticKeys1));
            sd.putKey(keyRef2, staticKeys2, keyRef1.getKvn());

            // there is only one SCP03 key
            Map<KeyRef, Map<Byte, Byte>> keyInformation = sd.getKeyInformation();
            assertNull(keyInformation.get(scp03EncOf(keyRef1)));
            assertNull(keyInformation.get(scp03MacOf(keyRef1)));
            assertNull(keyInformation.get(scp03DekOf(keyRef1)));

            assertNotNull(keyInformation.get(scp03EncOf(keyRef2)));
            assertNotNull(keyInformation.get(scp03MacOf(keyRef2)));
            assertNotNull(keyInformation.get(scp03DekOf(keyRef2)));
        });
    }

    private static KeyRef scp03EncOf(KeyRef key) {
        return new KeyRef((byte) 0x01, key.getKvn());
    }

    private static KeyRef scp03MacOf(KeyRef key) {
        return new KeyRef((byte) 0x02, key.getKvn());
    }

    private static KeyRef scp03DekOf(KeyRef key) {
        return new KeyRef((byte) 0x03, key.getKvn());
    }
}

/*
 * Copyright (C) 2024 Yubico.
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

package com.yubico.yubikit.testing.fido;

import com.yubico.yubikit.fido.ctap.PinUvAuthProtocol;
import com.yubico.yubikit.fido.ctap.PinUvAuthProtocolV1;
import com.yubico.yubikit.testing.PinUvAuthProtocolV1Test;
import com.yubico.yubikit.testing.fido.Extensions.ExtSignInstrumentedTests;
import com.yubico.yubikit.testing.fido.extensions.ExtCredBlobTests;
import com.yubico.yubikit.testing.fido.extensions.ExtCredPropsTests;
import com.yubico.yubikit.testing.fido.extensions.ExtHmacSecretTests;
import com.yubico.yubikit.testing.fido.extensions.ExtLargeBlobTests;
import com.yubico.yubikit.testing.fido.extensions.ExtPrfTests;
import com.yubico.yubikit.testing.framework.FidoInstrumentedTests;

import org.junit.Test;
import org.junit.experimental.categories.Category;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
        ExtensionsInstrumentedTests.PinUvAuthV2Test.class,
        ExtensionsInstrumentedTests.PinUvAuthV1Test.class,
        ExtSignInstrumentedTests.class
})
public class ExtensionsInstrumentedTests {
    public static class PinUvAuthV2Test extends FidoInstrumentedTests {
        @Test
        public void testCredPropsExtension() throws Throwable {
            withDevice(ExtCredPropsTests::test);
        }

        @Test
        public void testPrfExtension() throws Throwable {
            withDevice(ExtPrfTests::test);
        }

        @Test
        public void testPrfExtensionNoSupport() throws Throwable {
            withDevice(ExtPrfTests::testNoExtensionSupport);
        }

        @Test
        public void testHmacSecretExtension() throws Throwable {
            withDevice(ExtHmacSecretTests::test);
        }

        @Test
        public void testHmacSecretExtensionNoSupport() throws Throwable {
            withDevice(ExtHmacSecretTests::testNoExtensionSupport);
        }

        @Test
        public void testLargeBlobExtension() throws Throwable {
            withDevice(ExtLargeBlobTests::test);
        }

        @Test
        public void testCredBlobExtension() throws Throwable {
            withDevice(ExtCredBlobTests::test);
        }
    }

    @Category(PinUvAuthProtocolV1Test.class)
    public static class PinUvAuthV1Test extends PinUvAuthV2Test {
        @Override
        protected PinUvAuthProtocol getPinUvAuthProtocol() {
            return new PinUvAuthProtocolV1();
        }
    }
}

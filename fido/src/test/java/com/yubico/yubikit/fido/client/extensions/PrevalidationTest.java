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

package com.yubico.yubikit.fido.client.extensions;

import static com.yubico.yubikit.fido.client.extensions.ExtensionTestHelper.creation;
import static com.yubico.yubikit.fido.client.extensions.ExtensionTestHelper.request;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;

import com.yubico.yubikit.fido.client.ClientError;
import com.yubico.yubikit.fido.client.Ctap2Client;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

/**
 * Device-free pre-validation via {@link Ctap2Client#validateExtensionInputs}: request-shape
 * extension errors are raised from the request alone, with no {@link
 * com.yubico.yubikit.fido.ctap.Ctap2Session}, so a client can fail a doomed request before
 * connecting to a key. These are the same errors {@code makeCredential}/{@code getAssertion} raise
 * (see {@link LargeBlobExtensionTest} / {@link ExtensionHardFailTest}); here we assert they surface
 * from the default extension set without an authenticator.
 */
public class PrevalidationTest {

  private static final String LARGE_BLOB = "largeBlob";

  private static Map<String, ?> largeBlob(String key, Object value) {
    return Collections.singletonMap(LARGE_BLOB, Collections.singletonMap(key, value));
  }

  @Test
  public void writeWithoutExactlyOneCredentialIsRejected() throws Exception {
    // largeBlob write with an empty allow list (size != 1) -> NotSupportedError, no device needed.
    ClientError e =
        assertThrows(
            ClientError.class,
            () -> Ctap2Client.validateExtensionInputs(request(largeBlob("write", "AQ")), null));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, e.getErrorCode());
    assertTrue(e.getCause() instanceof ExtensionConfigurationException);
  }

  @Test
  public void supportDuringAuthenticationIsRejected() {
    ClientError e =
        assertThrows(
            ClientError.class,
            () ->
                Ctap2Client.validateExtensionInputs(
                    request(largeBlob("support", "preferred")), null));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, e.getErrorCode());
    assertTrue(e.getCause() instanceof ExtensionConfigurationException);
  }

  @Test
  public void readAndWriteTogetherIsRejected() {
    Map<String, Object> both = new HashMap<>();
    both.put("read", true);
    both.put("write", "AQ");
    ClientError e =
        assertThrows(
            ClientError.class,
            () ->
                Ctap2Client.validateExtensionInputs(
                    request(Collections.singletonMap(LARGE_BLOB, both)), null));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, e.getErrorCode());
    assertTrue(e.getCause() instanceof ExtensionConfigurationException);
  }

  @Test
  public void readWriteDuringRegistrationIsRejected() {
    ClientError e =
        assertThrows(
            ClientError.class,
            () -> Ctap2Client.validateExtensionInputs(creation(largeBlob("read", true)), null));
    assertEquals(ClientError.Code.CONFIGURATION_UNSUPPORTED, e.getErrorCode());
    assertTrue(e.getCause() instanceof ExtensionConfigurationException);
  }

  @Test
  public void validRequestPasses() throws Exception {
    // read is a valid authentication request; an empty request has nothing to validate.
    Ctap2Client.validateExtensionInputs(request(largeBlob("read", true)), null);
    Ctap2Client.validateExtensionInputs(request(Collections.emptyMap()), null);
    Ctap2Client.validateExtensionInputs(creation(Collections.emptyMap()), null);
  }
}

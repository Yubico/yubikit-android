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

package com.yubico.yubikit.fido.android.providerservice

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RelatedOriginRequestsUtilsTest {
    @Test
    fun `validateOrigin returns rpId url when callerOrigin is present`() {
        val callerOrigin = "https://example.com"
        val rpId = "example.com"
        val json = "{\"origins\":[\"https://example.com\",\"https://other.com\"]}"
        val mockFetcher: suspend (String) -> String = { json }
        val result = runBlocking { validateOrigin(callerOrigin, rpId, mockFetcher) }
        assertEquals("https://$rpId", result)
    }

    @Test
    fun `validateOrigin throws when callerOrigin is not present`() {
        val callerOrigin = "https://notfound.com"
        val rpId = "example.com"
        val json = "{\"origins\":[\"https://example.com\",\"https://other.com\"]}"
        val mockFetcher: suspend (String) -> String = { json }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { validateOrigin(callerOrigin, rpId, mockFetcher) }
        }
    }

    @Test
    fun `validateOrigin throws when fetcher throws`() {
        val callerOrigin = "https://example.com"
        val rpId = "example.com"
        val mockFetcher: suspend (String) -> String = { throw RuntimeException("Network error") }
        assertThrows(RuntimeException::class.java) {
            runBlocking { validateOrigin(callerOrigin, rpId, mockFetcher) }
        }
    }

    @Test
    fun `validateOrigin throws when origins is null`() {
        val callerOrigin = "https://example.com"
        val rpId = "example.com"
        val json = "{\"origins\":null}"
        val mockFetcher: suspend (String) -> String = { json }
        assertThrows(IllegalArgumentException::class.java) {
            runBlocking { validateOrigin(callerOrigin, rpId, mockFetcher) }
        }
    }
}

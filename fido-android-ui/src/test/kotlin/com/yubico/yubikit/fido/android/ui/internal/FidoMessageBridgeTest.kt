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

package com.yubico.yubikit.fido.android.ui.internal

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Unit tests for the reject-response JSON contract shared with fido.js. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class FidoMessageBridgeTest {

    @Test
    fun `error response carries the errorName when provided`() {
        val json = JSONObject(
            FidoMessageBridge.errorResponseJson(
                promiseUuid = "uuid-1",
                message = "This request isn't supported.",
                errorName = "NotSupportedError",
            ),
        )

        assertEquals("reject", json.getString("type"))
        assertEquals("uuid-1", json.getString("promiseUuid"))
        assertEquals("This request isn't supported.", json.getString("message"))
        // fido.js reads data.errorName to pick the DOMException name.
        assertEquals("NotSupportedError", json.getString("errorName"))
    }

    @Test
    fun `error response omits errorName when absent`() {
        val json = JSONObject(
            FidoMessageBridge.errorResponseJson(
                promiseUuid = "uuid-1",
                message = "The operation failed",
            ),
        )

        // No errorName -> fido.js defaults to NotAllowedError.
        assertFalse(json.has("errorName"))
    }
}

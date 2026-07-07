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

import android.app.Activity
import android.content.Intent
import com.yubico.yubikit.fido.android.ui.WebAuthnClientException
import kotlinx.coroutines.CancellationException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/** Unit tests for [parseFidoActivityResult] — the activity-result to [Result] mapping. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class FidoClientImplTest {

    @Test
    fun `RESULT_ERROR returns WebAuthnClientException carrying name and message`() {
        val intent = Intent()
            .putExtra(EXTRA_ERROR_NAME, "NotSupportedError")
            .putExtra(EXTRA_ERROR_MESSAGE, "largeBlob write requires exactly one allowed credential")

        val error = parseFidoActivityResult(RESULT_ERROR, intent).exceptionOrNull()

        assertTrue(error is WebAuthnClientException)
        error as WebAuthnClientException
        assertEquals("NotSupportedError", error.webAuthnError)
        assertEquals("largeBlob write requires exactly one allowed credential", error.message)
    }

    @Test
    fun `RESULT_ERROR without a name falls back to NotSupportedError`() {
        val error = parseFidoActivityResult(RESULT_ERROR, Intent()).exceptionOrNull()

        assertTrue(error is WebAuthnClientException)
        assertEquals("NotSupportedError", (error as WebAuthnClientException).webAuthnError)
        assertNull(error.message)
    }

    @Test
    fun `RESULT_CANCELED is a cancellation, not a WebAuthnClientException`() {
        val error = parseFidoActivityResult(Activity.RESULT_CANCELED, null).exceptionOrNull()

        assertTrue(error is CancellationException)
    }

    @Test
    fun `RESULT_OK returns the credential JSON`() {
        val intent = Intent().putExtra("credential", "{\"id\":\"abc\"}")

        val result = parseFidoActivityResult(Activity.RESULT_OK, intent)

        assertEquals("{\"id\":\"abc\"}", result.getOrNull())
    }
}

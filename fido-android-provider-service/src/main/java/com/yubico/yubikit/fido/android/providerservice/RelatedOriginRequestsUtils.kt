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

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import org.slf4j.LoggerFactory
import java.net.URL
import javax.net.ssl.HttpsURLConnection

@Serializable
data class WebAuthnWellKnownResponse(
    val origins: List<String>? = null,
)

private val logger = LoggerFactory.getLogger("RelatedOriginRequestsUtils")

internal suspend fun fetchWebauthnWellKnown(rpId: String): String =
    withContext(Dispatchers.IO) {
        val url = URL("https://$rpId/.well-known/webauthn")
        logger.debug("Reading {}", url)
        val conn = url.openConnection() as HttpsURLConnection

        conn.requestMethod = "GET"
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("Referer", "")
        conn.useCaches = false
        conn.connectTimeout = 5000
        conn.readTimeout = 5000

        try {
            val code = conn.responseCode
            val contentType = conn.contentType ?: ""
            if (code != 200 || !contentType.contains("application/json")) {
                throw IllegalArgumentException("Failed to validate origin")
            }
            conn.inputStream.bufferedReader().use { it.readText() }
        } catch (e: Throwable) {
            logger.debug("Failed read {}", url, e)
            throw e
        } finally {
            conn.disconnect()
        }
    }

// Main validation function
suspend fun validateOrigin(
    callerOrigin: String,
    rpId: String,
): String {
    runCatching {
        val body = fetchWebauthnWellKnown(rpId)

        val parsed: WebAuthnWellKnownResponse =
            Json.decodeFromString(WebAuthnWellKnownResponse.serializer(), body)
        parsed.origins?.let {
            logger.debug("There are {} related origins: {}", it.size, it)
            if (it.contains(callerOrigin)) {
                logger.debug("Found caller origin in related origins")
                return "https://$rpId"
            }
        }
        throw IllegalArgumentException("Failed to validate origin")
    }.getOrThrow()
}

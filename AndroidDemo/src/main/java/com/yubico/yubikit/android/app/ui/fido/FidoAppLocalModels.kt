/*
 * Copyright (C) 2025 Yubico.
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

package com.yubico.yubikit.android.app.ui.fido

import kotlinx.serialization.Serializable

@Serializable
data class Rp(val id: String, val name: String)

@Serializable
data class User(val id: String, val name: String, val displayName: String)

@Serializable
data class AuthenticatorSelection(
    val userVerification: String = "required",
    val residentKey: String = "required",
    val requireResidentKey: Boolean = true,
    val authenticatorAttachment: String = "cross-platform"
)

@Serializable
data class PubKeyCredParams(val alg: Int, val type: String = "public-key")

@Serializable
data class McRequest(
    val challenge: String,
    val rp: Rp,
    val user: User,
    val attestation: String = "direct",
    val authenticatorSelection: AuthenticatorSelection = AuthenticatorSelection(),
    val excludeCredentials: List<String> = emptyList(),
    val timeout: Int = 90000,
    val extensions: Map<String, Boolean> = mapOf("credProps" to true),
    val pubKeyCredParams: List<PubKeyCredParams> = listOf(
        PubKeyCredParams(alg = -8),
        PubKeyCredParams(alg = -7),
        PubKeyCredParams(alg = -257),
    )
)

@Serializable
data class GaRequest(
    val challenge: String,
    val rpId: String,
    val userVerification: String = "required",
    val timeout: Int = 90000,
    val allowCredentials: List<String> = emptyList()
)
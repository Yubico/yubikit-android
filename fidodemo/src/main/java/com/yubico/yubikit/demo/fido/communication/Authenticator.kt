/*
 * Copyright (C) 2019 Yubico.
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

package com.yubico.yubikit.demo.fido.communication

import com.squareup.moshi.Json
import java.util.*

data class Webauthn (
        @Json(name="deviceType")
    val deviceType : String,
        @Json(name="id")
    val id : String,
        @Json(name="lastUsed")
    val lastUsed : Date,
        @Json(name="metadata")
    val metadata : Metadata,
        @Json(name="name")
    val name : String,
        @Json(name="registeredAt")
    val registeredAt : Date,
        @Json(name="type")
    val type : String
)

data class Authenticators (
        @Json(name="webauthn")
        val webauthn :  List<Webauthn>? = null
)

data class AuthenticatorData (
    @Json(name="authenticators")
    val authenticators : Authenticators
)

data class AuthenticatorStatus (
        @Json(name="data")
    val authenticatorData : AuthenticatorData,

        @Json(name="status")
    val status : String
)

data class Metadata (
    @Json(name="authenticator_attachment")
    val authenticatorAttachment : String
)

data class RenameProperty (
        @Json(name="name")
        val name : String
)

data class JSONBlob(
        @Json(name = "type")
        val type : String,
        @Json(name = "challenge")
        val challenge : String,
        @Json(name = "origin")
        var origin : String,
        @Json(name = "androidPackageName")
        var androidPackageName: String?
)

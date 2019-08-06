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
import java.io.Serializable

data class UserCreds(
        @Json(name="username")
        val username: String,
        @Json(name="password")
        val password: String,
        @Json(name="namespace")
        val namespace: String
)

data class User(
        @Json(name="displayName")
        val displayName: String,
        @Json(name="username")
        val username: String,
        @Json(name="uuid")
        val uuid: String,
        @Json(name="authenticators")
        val authenticators: List<String>? = null) : Serializable {
        companion object {
                private const val serialVersionUID = 1L
        }
}


data class UserData(
        @Json(name="user")
        val user: User
)

data class LoginStatus(
        @Json(name="data")
        val userData: UserData,
        @Json(name="status")
        val status: String
)

data class UserStatus(
        @Json(name="data")
        val user: User,
        @Json(name="status")
        val status: String
)

data class OperationStatus(
        @Json(name="status")
        val status: String
)


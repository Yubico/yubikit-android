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

import retrofit2.Call
import retrofit2.http.*

interface NetworkApi {
    @Headers("Content-Type: application/json")
    @POST("/api/v1/auth/login")
    fun login(@Body user : UserCreds) : Call<LoginStatus>

    @POST("/api/v1/user")
    fun user(@Body user : UserCreds) : Call<UserStatus>

    @POST("/api/v1/user/{uuid}/logout")
    @Headers("Content-Type: application/json")
    fun logout(@Path("uuid") uuid: String) : Call<OperationStatus>

    @GET("api/v1/user/{uuid}/authenticator")
    @Headers("Content-Type: application/json")
    fun authenticator(@Path("uuid") uuid: String) : Call<AuthenticatorStatus>

    @POST("/api/v1/user/{uuid}/webauthn/register-begin")
    @Headers("Content-Type: application/json")
    fun registerBegin(@Path("uuid") uuid: String, @Body request: RegisterBeginRequest) : Call<RegisterBeginResponse>

    @POST("/api/v1/user/{uuid}/webauthn/register-finish")
    @Headers("Content-Type: application/json")
    fun registerFinish(@Path("uuid") uuid: String, @Body request: RegisterFinishRequest) : Call<RegisterFinishResponse>

    @POST("/api/v1/auth/webauthn/authenticate-begin")
    @Headers("Content-Type: application/json")
    fun authenticateBegin(@Body request: AuthBeginRequest) : Call<AuthBeginResponse>

    @POST("/api/v1/auth/webauthn/authenticate-finish")
    @Headers("Content-Type: application/json")
    fun authenticateFinish(@Body request: AuthFinishRequest) : Call<AuthFinishResponse>

    @DELETE("/api/v1/user/{uuid}/authenticator/{deviceid}")
    @Headers("Content-Type: application/json")
    fun delete(@Path("uuid") uuid: String, @Path("deviceid") deviceid: String) : Call<OperationStatus>

    @PATCH("/api/v1/user/{uuid}/authenticator/{deviceid}")
    @Headers("Content-Type: application/json")
    fun rename(@Path("uuid") uuid: String, @Path("deviceid") deviceid: String, @Body newName: RenameProperty) : Call<OperationStatus>
}
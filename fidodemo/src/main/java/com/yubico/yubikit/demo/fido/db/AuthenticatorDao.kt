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

package com.yubico.yubikit.demo.fido.db

import androidx.lifecycle.LiveData
import androidx.room.*
import com.squareup.moshi.Json
import com.yubico.yubikit.demo.fido.communication.Webauthn
import com.yubico.yubikit.demo.fido.settings.BuildConfig
import java.util.*

@Dao
interface AuthenticatorDao {
    @Transaction
    suspend fun setAuthenticators(authenticators: List<Webauthn>, uuid: String) {
        delete(uuid)
        insert(authenticators.map { Authenticator(it, uuid) })
    }

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(authenticators: List<Authenticator>)

    @Query("SELECT * FROM " + BuildConfig.TABLE_NAME + " WHERE uuid = :uuid")
    fun authenticator(uuid: String): LiveData<List<Authenticator>>

    @Query("SELECT * FROM " + BuildConfig.TABLE_NAME)
    fun authenticatorAll(): LiveData<List<Authenticator>>

    @Query("DELETE FROM " + BuildConfig.TABLE_NAME + " WHERE uuid = :uuid")
    suspend fun delete(uuid: String)

    @Query("DELETE FROM " + BuildConfig.TABLE_NAME)
    suspend fun deleteAll()
}

@Entity(tableName = BuildConfig.TABLE_NAME)
data class Authenticator (@Json(name="deviceType")
                          val deviceType : String,
                          @PrimaryKey
                          @Json(name="id")
                          val id : String,
                          @Json(name="lastUsed")
                          val lastUsed : Date,
                          @Json(name="attachment")
                          val attachment : String,
                          @Json(name="name")
                          val name : String,
                          @Json(name="registeredAt")
                          val registeredAt : Date,
                          @Json(name="type")
                          val type : String,
                          @Json(name="uuid")
                          val uuid: String) {
    constructor(webauthn: Webauthn, uuid: String) :
            this(webauthn.deviceType, webauthn.id, webauthn.lastUsed, webauthn.metadata.authenticatorAttachment, webauthn.name, webauthn.registeredAt, webauthn.type, uuid)
}

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

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters

/**
 * Database schema that holds the list of repos.
 */
@Database(
        entities = [Authenticator::class],
        version = 1,
        exportSchema = false)
@TypeConverters(Converters::class)
abstract class AuthenticatorDatabase : RoomDatabase() {

    abstract fun getDao(): AuthenticatorDao

    companion object {

        @Volatile
        private var INSTANCE: AuthenticatorDatabase? = null

        fun getInstance(context: Context): AuthenticatorDatabase =
                INSTANCE ?: synchronized(this) {
                    INSTANCE
                            ?: buildDatabase(context).also { INSTANCE = it }
                }

        private fun buildDatabase(context: Context) =
                Room.databaseBuilder(context.applicationContext,
                        AuthenticatorDatabase::class.java, "authenticator.db")
                        .build()
    }
}
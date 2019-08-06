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

package com.yubico.yubikit.demo.fido.arch

import android.content.Context
import com.yubico.yubikit.demo.fido.db.AuthenticatorDatabase
import com.yubico.yubikit.demo.fido.db.LocalCache
import com.yubico.yubikit.demo.fido.signin.AccountStorage
import com.yubico.yubikit.fido.Fido2ClientApi
import java.util.concurrent.Executors

object Injection {

    var localCache: LocalCache? = null
    /**
     * Creates an instance of [LocalCache] based on the database DAO.
     */
    fun provideCache(context: Context): LocalCache {
        if (localCache == null) {
            val database = AuthenticatorDatabase.getInstance(context)
            localCache = LocalCache(database.getDao(), Executors.newSingleThreadExecutor())
        }
        return localCache!!
    }

    /**
     * Creates an instance of [AccountStorage]
     */
    fun provideAccountStorage(context: Context): AccountStorage {
        return AccountStorage(context)
    }

    /**
     * Creates an instance of [Fido2ClientApi]
     */
    fun provideFidoClient(context: Context): Fido2ClientApi {
        return Fido2ClientApi(context)
    }
}
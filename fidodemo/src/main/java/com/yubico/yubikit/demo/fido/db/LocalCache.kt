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
import com.yubico.yubikit.demo.fido.communication.Webauthn
import kotlinx.coroutines.*
import java.util.concurrent.Executor

/**
 * Class that handles the DAO local data source. This ensures that methods are triggered on the
 * correct executor.
 */
class LocalCache(
        private val authenticatorDao: AuthenticatorDao,
        private val ioExecutor: Executor
) {
    /**
     * Insert a list of repos in the database, on a background thread.
     */
    fun insert(authenticators: List<Webauthn>, uuid: String, insertFinished: () -> Unit) {
        CoroutineScope(ioExecutor.asCoroutineDispatcher()).launch {
            authenticatorDao.setAuthenticators(authenticators, uuid)
            insertFinished()
        }
    }

    /**
     * Request a LiveData<List<Authenticator>> from the Dao, based on a user id.
     * @param name uuid
     */
    fun authenticatorByUser(name: String): LiveData<List<Authenticator>> {
        return authenticatorDao.authenticator(name)
    }

    /**
     * Clear all cache - use for test purposes to emulate behavior of lost cache
     */
    fun clearCache() {
        CoroutineScope(ioExecutor.asCoroutineDispatcher()).launch {
            authenticatorDao.deleteAll()
        }
    }
}
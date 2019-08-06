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

package com.yubico.yubikit.demo.fido.signin

import android.content.Context
import android.preference.PreferenceManager
import android.text.TextUtils
import android.util.Log
import com.squareup.moshi.Json
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.yubico.yubikit.demo.fido.communication.User
import com.yubico.yubikit.demo.fido.network.ByteArrayJsonAdapter

/**
 * Storage for accounts uses {@link SharedPreferences}
 */
class AccountStorage(context: Context) {

    private val moshi = Moshi.Builder().add(ByteArray::class.java, ByteArrayJsonAdapter())
            .add(KotlinJsonAdapterFactory())
            .build()

    private val preferences = PreferenceManager.getDefaultSharedPreferences(context)

    /**
     * Track an account that currently signed in
     */
    fun saveAccount(userData: User) {
        val accountString = moshi.adapter(User::class.java).toJson(userData)
        preferences.edit().putString(PREF_SIGNED_IN_ACCOUNT, accountString).apply()

        saveAccountInHistory(userData)
    }

    fun removeAccount() {
        preferences.edit().putString(PREF_SIGNED_IN_ACCOUNT, null).apply()
    }

    fun getAccount(): User? {
        val account = preferences.getString(PREF_SIGNED_IN_ACCOUNT, null)
        if (account != null && !account.isEmpty()) {
            val userData = moshi.adapter(User::class.java).fromJson(account)
            if (userData != null && !TextUtils.isEmpty(userData.uuid)) {
                return userData
            }
        }
        return null
    }

    /**
     * Keep track of accounts that registered platform authenticator and allowed to have passwordless login
     *
     * Note: this list might have false positives: accounts that don't have platform authenticator from this device or account doesn't exist
     * ex. authenticator was removed from another device/web app
     * or account was created on another device
     */
    fun savePasswordLessAccount(userData: User, credentialId: ByteArray, deviceId: String?) {
        val userDataString = moshi.adapter(AccountNoPwd::class.java).toJson(AccountNoPwd(userData))
        val credIdString = moshi.adapter(ByteArray::class.java).toJson(credentialId)
        val devId = deviceId ?: String()
        preferences.edit()
                .putString(PREF_PASSWORLESS_ACCOUNT, userDataString)
                .putString(userDataString, credIdString)
                .putString(PREF_DEVICE_ID, devId).apply()
        Log.d(TAG, "Saved passwordless account $userDataString")
    }

    fun removePasswordLessAccount(userData: User) {
        val userDataString = moshi.adapter(AccountNoPwd::class.java).toJson(AccountNoPwd(userData))
        preferences.edit()
                .putString(userDataString, String())
                .putString(PREF_PASSWORLESS_ACCOUNT, String())
                .putString(PREF_DEVICE_ID, String()).apply()
        Log.d(TAG, "Removed passwordless account $userDataString")
    }

    fun getPasswordLessAccount() : User? {
        var account = preferences.getString(PREF_PASSWORLESS_ACCOUNT, String())
        if (account == null || TextUtils.isEmpty(account)) {
            return null
        }

        // exclude accounts that were expired
        val timeOfCreation = getTimeOfCreation(account)
        if (isAccountExpired(timeOfCreation)) {
            return null
        }
        return moshi.adapter(AccountNoPwd::class.java).fromJson(account)?.toUser()
    }

    fun readCredentialId(userData: User): ByteArray? {
        val userDataString = moshi.adapter(AccountNoPwd::class.java).toJson(AccountNoPwd(userData))
        var credIdString = preferences.getString(userDataString, String())
        if (TextUtils.isEmpty(credIdString)) {
            return null
        }
        return moshi.adapter(ByteArray::class.java).fromJson(credIdString)
    }

    fun getDeviceId() : String {
        return preferences.getString(PREF_DEVICE_ID, String()) ?: String()
    }


    fun readHistory(): MutableSet<String> {
       var accounts = preferences.getStringSet(PREF_ACCOUNTS_HISTORY, HashSet<String>())
        if (accounts == null) {
            accounts = HashSet()
        }
        return accounts
    }

    private fun saveAccountInHistory(userData: User) {
        var accounts = preferences.getStringSet(PREF_ACCOUNTS_HISTORY, HashSet<String>())
        accounts?.add(userData.username)
        preferences.edit().putStringSet(PREF_ACCOUNTS_HISTORY, accounts).apply()

        // save time of account creation/first login on this device
        // if time is expired consider it is newly recreated account
        val userDataString = moshi.adapter(AccountNoPwd::class.java).toJson(AccountNoPwd(userData))
        val timeOfCreation = getTimeOfCreation(userDataString)
        if (timeOfCreation == 0L || isAccountExpired(timeOfCreation)) {
            saveTimeOfCreation(userDataString)
        }
    }
    /**
     * Demo server keeps an account only 24 hours,
     * if this account was added more than 24 hours it's not valid anymore
     *
     * Note: this won't track accounts that were created from another device or web app
     * But helps to keep list of passwordless accounts cleaner
     */
    private fun saveTimeOfCreation(userId: String) {
        var timestampPreferences = userId + PREF_ACCOUNTS_TIMESTAMP
        preferences.edit().putLong(timestampPreferences, System.currentTimeMillis()).apply()
    }

    private fun getTimeOfCreation(userId: String) : Long {
        var timestampPreferences = userId + PREF_ACCOUNTS_TIMESTAMP
        return preferences.getLong(timestampPreferences, 0L)
    }

    private fun isAccountExpired(dateOfCreation: Long) : Boolean {
        if (dateOfCreation == 0L) {
            return false
        }
        return (System.currentTimeMillis() - dateOfCreation) > MILLS_IN_A_DAY
    }

    /**
     * Helper class that allows to serialize/deserialize {@link User} without authenticators list
     * For persistence we don't need to keep authenticator list and Users are equal even if they have different list of authenticators
     * As we can't make @Json(name="authenticators") field transient, because it's used for communication with server
     * we have helper class that removes authenticators from Json conversion
     */
    private data class AccountNoPwd(@Json(name="displayName")
                                            val displayName: String,
                                            @Json(name="username")
                                            val username: String,
                                            @Json(name="uuid")
                                            val uuid: String) {
        constructor(userData: User) : this(userData.displayName, userData.username, userData.uuid)

        fun toUser() : User {
            return User(displayName, username, uuid)
        }
    }

    companion object {
        const val TAG = "AccountStorage"
        const val PREF_SIGNED_IN_ACCOUNT = "account"
        const val PREF_PASSWORLESS_ACCOUNT = "accountSession"
        const val PREF_DEVICE_ID = "deviceId"
        const val PREF_ACCOUNTS_TIMESTAMP = "timestamp"
        const val PREF_ACCOUNTS_HISTORY = "history"
        const val MILLS_IN_A_DAY = 24 * 60 * 60 * 1000
    }
}

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

package com.yubico.yubikit.demo.settings

import android.content.Context
import androidx.preference.PreferenceManager
import com.yubico.yubikit.demo.R

/**
 * Storage for settings and flags that need to be preserved in app after restart
 * uses {@link SharedPreferences}
 */
class SettingsStorage(context: Context) {
    private val preferences = PreferenceManager.getDefaultSharedPreferences(context)

    /**
     * Track selected drawer menu item
     */
    fun saveNavigationDestination(menuId: Int) {
        preferences.edit().putInt(PREF_DESTINATION, menuId).apply()
    }

    fun getNavigationDestination() : Int {
        return preferences.getInt(PREF_DESTINATION, R.id.piv_fragment)
    }

    /**
     * Track if we need to show first time experience hints (e.g. show drawer with demo options)
     */
    fun markApplicationVisited() {
        preferences.edit().putBoolean(PREF_FIRST_TIME_VISIT, false).apply()
    }

    fun isFirstTimeExperience() : Boolean {
        return preferences.getBoolean(PREF_FIRST_TIME_VISIT, true)
    }

    companion object {
        const val PREF_DESTINATION = "destination"
        const val PREF_FIRST_TIME_VISIT = "first_time"
    }
}
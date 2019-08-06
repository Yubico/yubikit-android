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

import android.os.Bundle
import androidx.preference.EditTextPreference
import com.yubico.yubikit.demo.R
import androidx.preference.PreferenceFragmentCompat
import androidx.preference.SwitchPreferenceCompat
import com.yubico.yubikit.demo.fido.db.AuthenticatorDatabase
import com.yubico.yubikit.demo.fido.db.LocalCache
import java.util.concurrent.Executors

/**
 * Preferences/Settings page
 * allows to tweak ramp values dynamically in app (turn on/off feature)
 */
class SettingsFragment : PreferenceFragmentCompat(){

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.settings, rootKey)
        (findPreference(com.yubico.yubikit.demo.fido.settings.Ramps.PASSWORDLESS_EXPERIENCE.name) as SwitchPreferenceCompat).isChecked =
                com.yubico.yubikit.demo.fido.settings.Ramps.PASSWORDLESS_EXPERIENCE.getValue(context) == true

        val timeoutRamp = findPreference(Ramps.CONNECTION_TIMEOUT.name) as EditTextPreference
        timeoutRamp.text = Ramps.CONNECTION_TIMEOUT.getValue(context).toString()

        findPreference(getString(R.string.clear_cache)).setOnPreferenceClickListener {
            val database = AuthenticatorDatabase.getInstance(it.context)
            val localCache = LocalCache(database.getDao(), Executors.newSingleThreadExecutor())
            localCache.clearCache()
            true
        }

        (findPreference(Ramps.OATH_USE_TOUCH.name) as SwitchPreferenceCompat).isChecked = Ramps.OATH_USE_TOUCH.getValue(context) == true
        (findPreference(Ramps.OATH_TRUNCATE.name) as SwitchPreferenceCompat).isChecked = Ramps.OATH_TRUNCATE.getValue(context) == true
    }
}
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

/**
 * Preferences/Settings page
 * allows to tweak ramp values dynamically in app (turn on/off feature)
 */
class SettingsFragment : PreferenceFragmentCompat(){

    override fun onCreatePreferences(savedInstanceState: Bundle?, rootKey: String?) {
        setPreferencesFromResource(R.xml.settings, rootKey)

        val timeoutRamp = findPreference<EditTextPreference>(Ramps.CONNECTION_TIMEOUT.name)
        timeoutRamp!!.text = Ramps.CONNECTION_TIMEOUT.getValue(context).toString()

        val retriesRamp = findPreference<EditTextPreference>(Ramps.PIV_NUM_RETRIES.name)
        retriesRamp!!.text = Ramps.PIV_NUM_RETRIES.getValue(context).toString()
        findPreference<SwitchPreferenceCompat>(Ramps.PIV_USE_DEFAULT_MGMT.name)!!.isChecked = Ramps.PIV_USE_DEFAULT_MGMT.getValue(context) == true

        findPreference<SwitchPreferenceCompat>(Ramps.OATH_USE_TOUCH.name)!!.isChecked = Ramps.OATH_USE_TOUCH.getValue(context) == true
        findPreference<SwitchPreferenceCompat>(Ramps.OATH_TRUNCATE.name)!!.isChecked = Ramps.OATH_TRUNCATE.getValue(context) == true
    }
}
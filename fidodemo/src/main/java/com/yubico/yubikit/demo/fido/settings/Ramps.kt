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

package com.yubico.yubikit.demo.fido.settings

import android.content.Context
import android.os.Build
import androidx.preference.PreferenceManager
import java.lang.NumberFormatException


class Ramps {
    companion object {
        // currently it's only local app settings and pre-build values but can be regulated by server in future
        val PASSWORDLESS_EXPERIENCE = Ramp("passwordless", !isEmulator())
        val EXPIRE_SESSION_ON_APP_START = Ramp("expiration", true)

        fun isEmulator(): Boolean {
            return (Build.FINGERPRINT.startsWith("generic")
                    || Build.FINGERPRINT.startsWith("unknown")
                    || Build.MODEL.contains("google_sdk")
                    || Build.MODEL.contains("Emulator")
                    || Build.MODEL.contains("Android SDK built for x86")
                    || Build.MANUFACTURER.contains("Genymotion")
                    || Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")
                    || "google_sdk" == Build.PRODUCT)
        }
    }

    class Ramp (private val key: String, private val defaultValue: Any) {
        private var value = defaultValue
        val name
            get() = key

        fun getValue(context: Context?) : Any {
            if (context != null) {
                if (defaultValue is Boolean) {
                    value = PreferenceManager.getDefaultSharedPreferences(context).getBoolean(key, defaultValue)
                } else if (defaultValue is String) {
                    value = PreferenceManager.getDefaultSharedPreferences(context).getString(key, defaultValue) ?: defaultValue
                } else if (defaultValue is Int) {
                    // shared preferences keeps edit text settings/preferences as strings
                    var valueString = PreferenceManager.getDefaultSharedPreferences(context).getString(key, defaultValue.toString()) ?: String()
                    try {
                        value = Integer.parseInt(valueString)
                    } catch (e: NumberFormatException) {
                        value = defaultValue
                    }
                }
            }
            return value
        }

    }
}
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

import com.yubico.yubikit.demo.fido.settings.Ramps

class Ramps {
    companion object {
        // currently it's only local app settings and pre-build values but can be regulated by server in future
        var CONNECTION_TIMEOUT = Ramps.Ramp("nfctimeout", 10000) //10 seconds
        val USE_CUSTOM_TABS = Ramps.Ramp("customtabs", true)
        val OATH_USE_TOUCH = Ramps.Ramp("use_touch", false)
        val OATH_TRUNCATE = Ramps.Ramp("truncate_totp", true)
        val OATH_NFC_SOUND = Ramps.Ramp("nfc_sound", true)
        val PIV_NUM_RETRIES = Ramps.Ramp("pin_retries", 10)
        val PIV_USE_DEFAULT_MGMT = Ramps.Ramp("mgmt_key", true)
    }
}
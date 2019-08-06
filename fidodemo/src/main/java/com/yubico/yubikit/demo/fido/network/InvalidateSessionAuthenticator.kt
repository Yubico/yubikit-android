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

package com.yubico.yubikit.demo.fido.network

import android.util.Log
import com.yubico.yubikit.demo.fido.signin.CookieStorage
import okhttp3.Authenticator
import okhttp3.Request
import okhttp3.Response
import okhttp3.Route

class InvalidateSessionAuthenticator : Authenticator {
    private val TAG = "Authenticator"

    override fun authenticate(route: Route?, response: Response): Request? {
        Log.e(TAG, "Detected authentication error ${response.code()} on ${response.request()?.url()}")
        // we assume that our session is expired, nuke cookies, so that we sign user our
        CookieStorage.invalidateCookies()
        return null
    }
}
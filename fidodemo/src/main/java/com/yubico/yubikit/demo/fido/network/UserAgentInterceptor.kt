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

import com.yubico.yubikit.demo.fido.settings.BuildConfig
import okhttp3.Interceptor
import okhttp3.Response

/**
 * Interceptor that adds User-Agent header to network request
 */
class UserAgentInterceptor : Interceptor {

    private val appName = BuildConfig.getAppName()
    private val appVersion = BuildConfig.getVersion()

    override fun intercept(chain: Interceptor.Chain): Response {
        val originalRequest = chain.request()
        val userAgent = "$appName/$appVersion " + System.getProperty("http.agent")
        val requestWithUserAgent = originalRequest.newBuilder()
                .header("User-Agent", userAgent)
                .build()
        return chain.proceed(requestWithUserAgent)
    }
}
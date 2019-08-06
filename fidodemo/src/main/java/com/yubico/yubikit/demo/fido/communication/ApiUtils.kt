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

package com.yubico.yubikit.demo.fido.communication

import com.squareup.moshi.Moshi
import com.squareup.moshi.adapters.Rfc3339DateJsonAdapter
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.yubico.yubikit.demo.fido.network.ByteArrayJsonAdapter
import com.yubico.yubikit.demo.fido.network.CookieHandler
import com.yubico.yubikit.demo.fido.network.InvalidateSessionAuthenticator
import com.yubico.yubikit.demo.fido.network.UserAgentInterceptor
import com.yubico.yubikit.demo.fido.settings.BuildConfig
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import java.util.*
import java.util.concurrent.TimeUnit


class ApiUtils {
    companion object {
        private fun getOkHttpClient() : OkHttpClient {
            return OkHttpClient.Builder()
                    .cookieJar(CookieHandler())
                    .authenticator(InvalidateSessionAuthenticator())
                    .addInterceptor(UserAgentInterceptor())
                    .addInterceptor(HttpLoggingInterceptor().apply { level = HttpLoggingInterceptor.Level.BODY })
                    .retryOnConnectionFailure(true)
                    .readTimeout(10, TimeUnit.SECONDS)
                    .connectTimeout(10, TimeUnit.SECONDS)
                    .writeTimeout(10, TimeUnit.SECONDS)
                    .build()
        }

        /**
         * Provides interface to communicate with server {@link Constants.SERVER_URL}
         * Uses default okHttpClient
         */
        fun getApiService() : NetworkApi {
            return getApiService(getOkHttpClient())
        }

        /**
         * Provides interface to communicate with server {@link Constants.SERVER_URL}
         * Allows to provide custom okHttpClient
         */
        fun getApiService(okHttpClient : OkHttpClient) : NetworkApi {
            return  Retrofit.Builder()
                    .baseUrl(BuildConfig.getServerUrl())
                    .client(okHttpClient)
                    .addConverterFactory(MoshiConverterFactory.create(
                            Moshi.Builder()
                                    .add(KotlinJsonAdapterFactory())
                                    .add(Date::class.java, Rfc3339DateJsonAdapter())
                                    .add(ByteArray::class.java, ByteArrayJsonAdapter())
                                    .build()
                    ))
                    .build().create(NetworkApi::class.java)
        }
    }
}
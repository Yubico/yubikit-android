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

package com.yubico.yubikit.demo.otp

import android.content.Context
import android.os.AsyncTask
import android.text.TextUtils
import com.squareup.moshi.Json
import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.yubico.yubikit.demo.fido.network.DataException
import com.yubico.yubikit.demo.fido.network.ServiceCallback

import com.yubico.yubikit.otp.R
import okhttp3.OkHttpClient

import org.json.JSONException
import org.json.JSONObject
import retrofit2.Call
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import retrofit2.http.Body
import retrofit2.http.Headers

import java.io.BufferedReader
import java.io.IOException
import java.io.InputStream
import java.io.InputStreamReader
import java.io.OutputStream
import java.net.MalformedURLException
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicReference

import javax.net.ssl.HttpsURLConnection

import retrofit2.http.POST

/**
 * Sample network request to
 * https://demo.yubico.com/api/v1/simple/otp/validate
 * input: {key: "ccccccjehedvvcnfbnnjbbicenfbhvnulkrflcbitifv"}
 * output: {
 * data: {
 * nonce: "Ht56CNm36HXXqV1RZe3GchgBs"
 * otp: "ccccccjehedvvcnfbnnjbbicenfbhvnulkrflcbitifv"
 * sl: "25"
 * status: "OK"
 * t: "2019-06-12T04:31:54Z0798"
 * }
 * status: "success"
 * }
 * Or error cases:
 * {"data":{"reason":"NO_VALID_ANSWERS"},"message":"NO_VALID_ANSWERS","status":"error"}
 * {"message":"REPLAYED_OTP","status":"error"}
 */
private const val SERVER_URL = "https://demo.yubico.com/"
private const val SUCCESS = "success"
class YubiCloudValidator {

    /**
     * Verifies if input is valid Yubi OTP
     * @param key the key that needs to be verified
     * @param listener listener that will be invoked on UI thread upon completion of verification process
     */
    fun verify(key: String, listener: Listener) {
        val retrofit = Retrofit.Builder().baseUrl(SERVER_URL)
                .addConverterFactory(MoshiConverterFactory.create(
                        Moshi.Builder()
                                .add(KotlinJsonAdapterFactory())
                                .build()
                )).build()
        val service = retrofit.create(YubiCloudService::class.java)
        service.validateKey(Request(key)).enqueue(object : ServiceCallback<Response>() {
            override fun onFailure(call: Call<Response>, t: Throwable) {
                listener.onFailure(t)
            }

            override fun onResponse(call: Call<Response>, response: retrofit2.Response<Response>) {
                if (!handledErrorResponse(call, response)) {
                    if (!SUCCESS.equals(response.body()?.status, ignoreCase = true)) {
                        val message = response.body()?.message
                        listener.onFailure(DataException(message ?: "UNKNOWN_ERROR"))
                    } else {
                        listener.onSuccess()
                    }

                }
            }
        })
    }

    data class Response (
            @Json(name="message")
            val message: String?,
            @Json(name="status")
            val status: String?
    )

    data class Request (
            @Json(name="key")
            val key: String
    )

    interface YubiCloudService {
        @Headers("Content-Type: application/json")
        @POST("api/v1/simple/otp/validate")
        fun validateKey(@Body key: Request) : Call<Response>
    }

    /**
     * Listener that needs to be implemented to be notified about completion of verification process
     */
    interface Listener {
        fun onSuccess()
        fun onFailure(e: Throwable)
    }

}
